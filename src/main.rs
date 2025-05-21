use axum::{
    routing::{get, post},
    Router,
    extract::State,
    response::{Response, IntoResponse},
    http::{StatusCode, header},
    body::Body,
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
            sleep(Duration::from_secs(5*60)).await; // 每分钟检查一次
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
