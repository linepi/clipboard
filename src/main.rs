use axum::{
    routing::{get, post},
    Router,
    extract::State,
    response::{Response, IntoResponse, Html},
    http::{StatusCode, header},
    body::Body,
    Form,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio;
use tokio::net::TcpListener;
use tokio::time::sleep;

// 用于客户端传输剪贴板内容的结构体
#[derive(Serialize, Deserialize)]
struct ClipboardContent {
    text: String,
}

// 包含内容和最后更新时间的剪贴板数据结构
struct ClipboardData {
    content: String,
    last_updated: Instant,
}

impl ClipboardData {
    fn new(content: String) -> Self {
        Self {
            content,
            last_updated: Instant::now(),
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_updated.elapsed() > timeout
    }

    fn update(&mut self, content: String) {
        self.content = content;
        self.last_updated = Instant::now();
    }
}

// 用于在多个处理函数间共享剪贴板内容的结构体
#[derive(Clone)]
struct AppState {
    internal_clipboard: Arc<Mutex<Option<ClipboardData>>>,
}

#[tokio::main]
async fn main() {
    // 初始化共享状态，开始时内部剪贴板为空
    let shared_state = AppState {
        internal_clipboard: Arc::new(Mutex::new(None)),
    };

    // 启动超时清理任务
    let cleanup_state = shared_state.clone();
    tokio::spawn(async move {
        let timeout = Duration::from_secs(30 * 60); // 30分钟
        loop {
            sleep(Duration::from_secs(5*60)).await; // 每5分钟检查一次
            let mut clipboard = cleanup_state.internal_clipboard.lock().unwrap();
            if let Some(data) = clipboard.as_ref() {
                if data.is_expired(timeout) {
                    println!("剪贴板数据已过期，清除数据");
                    *clipboard = None;
                }
            }
        }
    });

    // 定义路由
    let app = Router::new()
        .route("/paste", post(paste_handler)) // POST /paste 用于从客户端接收剪贴板内容
        .route("/copy", get(copy_handler))   // GET /copy 用于将服务器剪贴板内容返回给客户端
        .route("/web/paste", get(web_paste_page)) // GET /web/paste 返回HTML粘贴页面
        .route("/web/paste", post(web_paste_handler)) // POST /web/paste 处理HTML表单提交
        .route("/web/copy", get(web_copy_page)) // GET /web/copy 返回HTML复制页面
        .with_state(shared_state);          // 将共享状态注入到路由

    // 定义监听地址和端口
    let addr = SocketAddr::from(([0, 0, 0, 0], 8355));
    println!("服务正在监听于 {}...", addr);

    // 启动服务
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

// 处理 /paste 请求：从客户端接收剪贴板内容并存储到服务器
async fn paste_handler(
    State(state): State<AppState>,
    body: Body,
) -> impl IntoResponse {
    // 读取请求体为字节
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("读取请求体失败: {:?}", err);
            return (StatusCode::BAD_REQUEST, "读取请求体失败").into_response();
        }
    };

    // 将字节转换为UTF-8字符串
    let text_content = match String::from_utf8(bytes.to_vec()) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("请求体不是有效的UTF-8文本: {:?}", err);
            return (StatusCode::BAD_REQUEST, "请求体不是有效的UTF-8文本").into_response();
        }
    };

    let mut clipboard = state.internal_clipboard.lock().unwrap();
    
    if let Some(data) = clipboard.as_mut() {
        data.update(text_content.clone());
    } else {
        *clipboard = Some(ClipboardData::new(text_content.clone()));
    }
    
    println!("已从客户端接收剪贴板内容: {}", text_content);
    
    // 返回纯文本的"Ok"
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body("Ok\n".to_string())
        .unwrap()
        .into_response()
}

// 处理 /copy 请求：将服务器存储的剪贴板内容返回给客户端（纯文本格式）
async fn copy_handler(
    State(state): State<AppState>, // 提取共享状态
) -> impl IntoResponse {
    let clipboard = state.internal_clipboard.lock().unwrap();
    
    match clipboard.as_ref() {
        Some(data) => {
            println!("将剪贴板内容发送给客户端: {}", data.content);
            
            // 创建一个纯文本响应
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(data.content.clone())
                .unwrap()
                .into_response()
        }
        None => {
            println!("剪贴板为空或已过期");
            
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body("剪贴板为空或数据已过期".to_string())
                .unwrap()
                .into_response()
        }
    }
}

// HTML粘贴表单数据结构
#[derive(Deserialize)]
struct PasteForm {
    content: String,
}

// 返回HTML粘贴页面
async fn web_paste_page() -> Html<String> {
    Html(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>剪贴板 - 粘贴内容</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 2rem;
                line-height: 1.5;
                color: #333;
                background-color: #f7f7f7;
            }
            h1 {
                color: #2c3e50;
                margin-bottom: 1.5rem;
                font-weight: 600;
            }
            .card {
                background: white;
                border-radius: 8px;
                padding: 2rem;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            textarea {
                width: 100%;
                min-height: 200px;
                padding: 1rem;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: inherit;
                font-size: 16px;
                margin-bottom: 1rem;
                box-sizing: border-box;
                resize: vertical;
            }
            button {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 16px;
                border-radius: 4px;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            button:hover {
                background-color: #45a049;
            }
            .button-container {
                display: flex;
                justify-content: flex-end;
            }
            .message {
                margin-top: 1rem;
                padding: 1rem;
                border-radius: 4px;
                display: none;
            }
            .success {
                background-color: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            .error {
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            .nav {
                display: flex;
                justify-content: space-between;
                margin-bottom: 1.5rem;
            }
            .nav a {
                color: #4CAF50;
                text-decoration: none;
            }
            .nav a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="nav">
            <h1>剪贴板服务 - 粘贴内容</h1>
            <div>
                <a href="/web/copy">查看剪贴板</a>
            </div>
        </div>
        <div class="card">
            <form action="/web/paste" method="post">
                <textarea name="content" placeholder="输入要保存到剪贴板的内容..." autofocus required></textarea>
                <div class="button-container">
                    <button type="submit">保存到剪贴板</button>
                </div>
            </form>
            <div id="message" class="message"></div>
        </div>
        <script>
            // 检查URL参数是否有成功或错误消息
            const urlParams = new URLSearchParams(window.location.search);
            const status = urlParams.get('status');
            const messageDiv = document.getElementById('message');
            
            if (status === 'success') {
                messageDiv.textContent = '内容已成功保存到剪贴板！';
                messageDiv.className = 'message success';
                messageDiv.style.display = 'block';
            } else if (status === 'error') {
                messageDiv.textContent = '保存到剪贴板时出错，请重试。';
                messageDiv.className = 'message error';
                messageDiv.style.display = 'block';
            }
        </script>
    </body>
    </html>
    "#.to_string())
}

// 处理HTML粘贴表单提交
async fn web_paste_handler(
    State(state): State<AppState>,
    Form(form): Form<PasteForm>,
) -> impl IntoResponse {
    let mut clipboard = state.internal_clipboard.lock().unwrap();
    
    if let Some(data) = clipboard.as_mut() {
        data.update(form.content.clone());
    } else {
        *clipboard = Some(ClipboardData::new(form.content.clone()));
    }
    
    println!("已从Web界面接收剪贴板内容");
    
    // 重定向回粘贴页面，带上成功状态
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/web/paste?status=success")
        .body("".to_string())
        .unwrap()
        .into_response()
}

// 返回HTML复制页面，自动复制内容到客户端剪贴板
async fn web_copy_page(
    State(state): State<AppState>,
) -> Html<String> {
    let clipboard = state.internal_clipboard.lock().unwrap();
    
    let (content, status_message) = match clipboard.as_ref() {
        Some(data) => {
            println!("从Web界面请求剪贴板内容");
            (data.content.clone(), "加载剪贴板内容完成")
        },
        None => {
            println!("剪贴板为空或已过期 (Web界面请求)");
            (String::new(), "剪贴板内容为空或已过期")
        }
    };
    
    let has_content = !content.is_empty();
    
    // 生成包含自动复制脚本的HTML
    let html = format!(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>剪贴板 - 复制内容</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 2rem;
                line-height: 1.5;
                color: #333;
                background-color: #f7f7f7;
            }}
            h1 {{
                color: #2c3e50;
                margin-bottom: 1.5rem;
                font-weight: 600;
            }}
            .card {{
                background: white;
                border-radius: 8px;
                padding: 2rem;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            textarea {{
                width: 100%;
                min-height: 200px;
                padding: 1rem;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: inherit;
                font-size: 16px;
                margin-bottom: 1rem;
                box-sizing: border-box;
                resize: vertical;
            }}
            .button {{
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 12px 24px;
                font-size: 16px;
                border-radius: 4px;
                cursor: pointer;
                transition: background-color 0.3s;
                display: inline-block;
                text-decoration: none;
                text-align: center;
            }}
            .button:hover {{
                background-color: #45a049;
            }}
            .button.secondary {{
                background-color: #2196F3;
            }}
            .button.secondary:hover {{
                background-color: #0b7dda;
            }}
            .button-container {{
                display: flex;
                justify-content: space-between;
                margin-top: 1rem;
            }}
            .status {{
                margin-top: 1rem;
                padding: 1rem;
                border-radius: 4px;
                background-color: {status_color};
                color: {text_color};
                border: 1px solid {border_color};
            }}
            .empty-message {{
                text-align: center;
                padding: 3rem 1rem;
                color: #666;
            }}
            .nav {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 1.5rem;
            }}
            .nav a {{
                color: #4CAF50;
                text-decoration: none;
            }}
            .nav a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="nav">
            <h1>剪贴板服务 - 复制内容</h1>
            <div>
                <a href="/web/paste">粘贴新内容</a>
            </div>
        </div>
        <div class="card">
            {content_html}
            <div id="statusMessage" class="status">{status_message}</div>
            <div class="button-container">
                <a href="/web/paste" class="button secondary">粘贴新内容</a>
                {copy_button}
            </div>
        </div>
        <script>
            {copy_script}
        </script>
    </body>
    </html>
    "#, 
    status_color = if has_content { "#d4edda" } else { "#f8d7da" },
    text_color = if has_content { "#155724" } else { "#721c24" },
    border_color = if has_content { "#c3e6cb" } else { "#f5c6cb" },
    content_html = if has_content {
        format!(r#"<textarea id="content" readonly>{}</textarea>"#, html_escape::encode_text(&content))
    } else {
        r#"<div class="empty-message">剪贴板中没有内容</div>"#.to_string()
    },
    status_message = status_message,
    copy_button = if has_content {
        r#"<button id="copyButton" class="button">复制内容</button>"#
    } else {
        ""
    },
    copy_script = if has_content {
        r#"
            document.addEventListener('DOMContentLoaded', () => {
                const content = document.getElementById('content');
                const copyButton = document.getElementById('copyButton');
                const statusMessage = document.getElementById('statusMessage');
                
                // 使用更现代的Clipboard API
                async function copyToClipboard() {
                    try {
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            // 优先使用现代的Clipboard API
                            await navigator.clipboard.writeText(content.value);
                            updateStatus('内容已复制到您的剪贴板！', 'success');
                        } else {
                            // 回退到老方法
                            content.select();
                            document.execCommand('copy');
                            updateStatus('内容已复制到您的剪贴板！', 'success');
                        }
                    } catch (err) {
                        console.error('复制失败:', err);
                        updateStatus('点击"复制内容"按钮将内容复制到剪贴板', 'warning');
                    }
                }
                
                function updateStatus(message, type) {
                    statusMessage.textContent = message;
                    if (type === 'success') {
                        statusMessage.style.backgroundColor = '#d4edda';
                        statusMessage.style.color = '#155724';
                        statusMessage.style.borderColor = '#c3e6cb';
                    } else if (type === 'warning') {
                        statusMessage.style.backgroundColor = '#fff3cd';
                        statusMessage.style.color = '#856404';
                        statusMessage.style.borderColor = '#ffeeba';
                    }
                }
                
                
                // 设置手动复制按钮事件
                copyButton.addEventListener('click', copyToClipboard);

                // 尝试自动复制
                copyToClipboard();
                
                // 也可以尝试自动聚焦到内容，方便用户手动复制
                content.focus();
                content.select();
            });
        "#
    } else {
        ""
    });
    
    Html(html)
}
