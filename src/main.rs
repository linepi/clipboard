use axum::{
    routing::{get, post},
    Router,
    extract::{State, ConnectInfo},
    response::{Response, IntoResponse, Html},
    http::{StatusCode, header, HeaderMap},
    body::Body,
    Form,
    middleware::{self, Next},
};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use chrono::Local;
use tokio;
use tokio::net::TcpListener;
use tokio::time::sleep;
use log::{info, error};
use env_logger;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use reqwest;
use std::sync::RwLock;

const LOG_FILE_PATH: &str = "/var/log/clipboard_service";
const LOG_FILE_MAX_SIZE: usize = 10 * 1024 * 1024; // 10MB

// IP-API 响应结构
#[derive(Debug, Deserialize, Clone)]
struct IpApiResponse {
    status: String,
    country: Option<String>,
    countryCode: Option<String>,
    region: Option<String>,
    regionName: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    as_name: Option<String>,
    query: String,
}

// IP地理位置缓存结构
struct IpGeoCache {
    cache: HashMap<IpAddr, (IpApiResponse, Instant)>,
    ttl: Duration, // 缓存有效期
}

impl IpGeoCache {
    fn new(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }
    
    fn get(&mut self, ip: &IpAddr) -> Option<IpApiResponse> {
        if let Some((data, timestamp)) = self.cache.get(ip) {
            // 检查缓存是否过期
            if timestamp.elapsed() < self.ttl {
                return Some(data.clone());
            }
            // 过期则移除
            self.cache.remove(ip);
        }
        None
    }
    
    fn set(&mut self, ip: IpAddr, data: IpApiResponse) {
        self.cache.insert(ip, (data, Instant::now()));
    }
    
    // 清理过期缓存
    fn cleanup(&mut self) {
        let expired_keys: Vec<IpAddr> = self.cache
            .iter()
            .filter(|(_, (_, timestamp))| timestamp.elapsed() > self.ttl)
            .map(|(ip, _)| *ip)
            .collect();
            
        for key in expired_keys {
            self.cache.remove(&key);
        }
    }
}

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

// 日志文件结构体
struct LogFile {
    file: File,
    path: String,
    current_size: AtomicUsize,
    log_index: AtomicUsize,
}

impl LogFile {
    fn new(log_dir_path_str: &str) -> Result<Self, std::io::Error> {
        let log_dir = Path::new(log_dir_path_str);

        // 确保日志目录存在
        if !log_dir.exists() {
            std::fs::create_dir_all(log_dir)?;
            info!("创建日志目录: {}", log_dir.display());
        } else if !log_dir.is_dir() {
            // 如果路径存在但不是目录，则返回错误
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                format!("日志路径 {} 已存在但不是一个目录", log_dir.display())
            ));
        }

        // 扫描目录以确定下一个日志文件的索引
        let mut max_index: i64 = -1; // 使用 i64 以处理潜在的解析错误或空目录
        for entry_result in std::fs::read_dir(log_dir)? {
            let entry = entry_result?;
            let path = entry.path();
            if path.is_file() {
                // 从文件名（如 "3.log"）中提取索引 "3"
                if let Some(file_stem_osstr) = path.file_stem() {
                    if let Some(file_stem_str) = file_stem_osstr.to_str() {
                        if let Ok(index) = file_stem_str.parse::<i64>() {
                            // 确保扩展名是 .log
                            if path.extension().and_then(|s| s.to_str()) == Some("log") {
                                if index > max_index {
                                    max_index = index;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        let current_log_index = (max_index + 1).max(0) as usize; // 确保索引至少为0

        // 创建初始日志文件路径
        let file_path = log_dir.join(format!("{}.log", current_log_index));
        
        info!("日志服务将使用文件: {}", file_path.display());

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
            
        let metadata = file.metadata()?;
        let current_file_size = metadata.len() as usize;
        
        Ok(LogFile {
            file,
            path: log_dir_path_str.to_string(), // 存储日志目录的路径字符串
            current_size: AtomicUsize::new(current_file_size),
            log_index: AtomicUsize::new(current_log_index), // 使用计算得到的索引
        })
    }
    
    fn write(&mut self, content: &str) -> Result<(), std::io::Error> {
        let content_bytes = content.as_bytes();
        let content_len = content_bytes.len();
        
        let current_size = self.current_size.load(Ordering::Relaxed);
        if current_size + content_len > LOG_FILE_MAX_SIZE {
            let new_index = self.log_index.fetch_add(1, Ordering::SeqCst) + 1;
            
            // 使用存储的目录路径和新索引创建新文件名
            let log_dir = Path::new(&self.path);
            let new_file_path = log_dir.join(format!("{}.log", new_index));
            
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&new_file_path)?;
                
            self.current_size.store(0, Ordering::SeqCst);
            
            info!("创建新的日志文件: {}", new_file_path.display());
        }
        
        self.file.write_all(content_bytes)?;
        self.file.flush()?;
        
        self.current_size.fetch_add(content_len, Ordering::SeqCst);
        
        Ok(())
    }
}

// 用于在多个处理函数间共享剪贴板内容和日志文件的结构体
#[derive(Clone)]
struct AppState {
    internal_clipboard: Arc<Mutex<Option<ClipboardData>>>,
    log_file: Arc<Mutex<LogFile>>,
    ip_cache: Arc<RwLock<IpGeoCache>>,
    http_client: reqwest::Client,
}

// 获取真实IP地址
fn get_real_ip(headers: &HeaderMap, socket_addr: SocketAddr) -> IpAddr {
    // 尝试从X-Forwarded-For头获取
    if let Some(forwarded) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    
    // 尝试从X-Real-IP头获取
    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    
    // 使用socket地址作为后备
    socket_addr.ip()
}

// 查询IP地理位置信息
async fn query_ip_location(ip: IpAddr, state: &AppState) -> String {
    // 跳过私有IP或环回地址
    let is_private = match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_unspecified(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    };
    
    if is_private {
        return "本地网络".to_string();
    }
    
    // 尝试从缓存获取
    if let Ok(mut cache) = state.ip_cache.write() {
        if let Some(cached_data) = cache.get(&ip) {
            return format_location(&cached_data);
        }
    }
    
    // 构建API请求URL
    let api_url = format!("http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query&lang=zh-CN", ip);
    
    // 发送请求
    match state.http_client.get(&api_url).send().await {
        Ok(response) => {
            match response.json::<IpApiResponse>().await {
                Ok(data) => {
                    // 检查API响应状态
                    if data.status == "success" {
                        // 缓存结果
                        if let Ok(mut cache) = state.ip_cache.write() {
                            cache.set(ip, data.clone());
                        }
                        
                        // 格式化位置信息
                        format_location(&data)
                    } else {
                        "地理位置查询失败".to_string()
                    }
                },
                Err(e) => {
                    error!("解析IP-API响应失败: {}", e);
                    "地理位置解析错误".to_string()
                }
            }
        },
        Err(e) => {
            error!("IP-API请求失败: {}", e);
            "地理位置查询错误".to_string()
        }
    }
}

// 格式化位置信息
fn format_location(data: &IpApiResponse) -> String {
    let mut parts = Vec::new();
    
    // 添加城市
    if let Some(ref city) = data.city {
        if !city.is_empty() {
            parts.push(city.clone());
        }
    }
    
    // 添加地区
    if let Some(ref region_name) = data.regionName {
        if !region_name.is_empty() && !parts.contains(region_name) {
            parts.push(region_name.clone());
        }
    }
    
    // 添加国家
    if let Some(ref country) = data.country {
        if !country.is_empty() && !parts.contains(country) {
            parts.push(country.clone());
        }
    }
    
    // 添加ISP
    if let Some(ref isp) = data.isp {
        if !isp.is_empty() {
            parts.push(format!("ISP: {}", isp));
        }
    }
    
    if parts.is_empty() {
        "未知位置".to_string()
    } else {
        parts.join(", ")
    }
}

// 日志中间件
async fn log_middleware(
    State(state): State<AppState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    
    // 获取真实客户端IP
    let real_ip = get_real_ip(&headers, socket_addr);
    
    // 获取用户代理信息
    let ua_string = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");
    
    // 获取IP地理位置信息
    let geo_info = query_ip_location(real_ip, &state).await;
    
    // 生成请求日志前缀
    let log_prefix = format!(
        "[{}] [{}] [{}] [{} {}] [{}]",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        real_ip,
        ua_string,
        method,
        path,
        geo_info
    );
    
    // 继续处理请求
    let response = next.run(req).await;
    
    // 记录请求完成时间
    let duration = start.elapsed();
    let status = response.status();
    
    let log_entry = format!("{} - Status: {} - Duration: {:?}\n", log_prefix, status, duration);
    info!("{}", log_entry.trim());
    
    // 写入日志文件
    if let Ok(ref mut log_file) = state.log_file.lock() {
        if let Err(e) = log_file.write(&log_entry) {
            error!("写入日志文件失败: {}", e);
        }
    }
    
    response
}

// 记录剪贴板内容的函数
async fn log_clipboard_content(state: &AppState, content: &str, operation: &str, ip: IpAddr) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    // 获取IP地理位置
    let geo_info = query_ip_location(ip, state).await;
    
    let log_entry = format!(
        "[{}] [{}] [{}] [{}] 剪贴板内容: {}\n",
        timestamp,
        ip,
        operation,
        geo_info,
        content
    );
    
    info!("{}", log_entry.trim());
    
    // 写入日志文件
    if let Ok(ref mut log_file) = state.log_file.lock() {
        if let Err(e) = log_file.write(&log_entry) {
            error!("写入剪贴板内容日志失败: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志系统
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
    
    // 创建日志文件
    info!("初始化日志目录: {}", LOG_FILE_PATH);
    let log_file = LogFile::new(LOG_FILE_PATH)?;
    
    // 创建HTTP客户端
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    // 初始化IP地理位置缓存 (24小时TTL)
    let ip_cache = IpGeoCache::new(Duration::from_secs(24 * 60 * 60));
    
    // 初始化共享状态
    let shared_state = AppState {
        internal_clipboard: Arc::new(Mutex::new(None)),
        log_file: Arc::new(Mutex::new(log_file)),
        ip_cache: Arc::new(RwLock::new(ip_cache)),
        http_client,
    };
    
    // 启动缓存清理任务
    let cache_cleanup_state = shared_state.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60 * 60)).await; // 每小时清理一次
            if let Ok(mut cache) = cache_cleanup_state.ip_cache.write() {
                cache.cleanup();
                info!("已清理过期的IP地理位置缓存");
            }
        }
    });

    // 启动超时清理任务
    let clipboard_cleanup_state = shared_state.clone();
    tokio::spawn(async move {
        let timeout = Duration::from_secs(30 * 60); // 30分钟
        loop {
            sleep(Duration::from_secs(5*60)).await; // 每5分钟检查一次
            let mut clipboard = clipboard_cleanup_state.internal_clipboard.lock().unwrap();
            if let Some(data) = clipboard.as_ref() {
                if data.is_expired(timeout) {
                    info!("剪贴板数据已过期，清除数据");
                    *clipboard = None;
                }
            }
        }
    });

    // 定义路由
    let app = Router::new()
        .route("/paste", post(paste_handler)) 
        .route("/copy", get(copy_handler))   
        .route("/web/paste", get(web_paste_page))
        .route("/web/paste", post(web_paste_handler))
        .route("/web/copy", get(web_copy_page))
        .layer(middleware::from_fn_with_state(shared_state.clone(), log_middleware))
        .with_state(shared_state)
        .into_make_service_with_connect_info::<SocketAddr>();

    // 定义监听地址和端口
    let addr = SocketAddr::from(([0, 0, 0, 0], 8355));
    info!("服务正在监听于 {}...", addr);

    // 启动服务
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await?;
        
    Ok(())
}

// 处理 /paste 请求：从客户端接收剪贴板内容并存储到服务器
async fn paste_handler(
    State(state): State<AppState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    // 获取真实客户端IP
    let real_ip = get_real_ip(&headers, socket_addr);
    
    // 读取请求体为字节
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!("读取请求体失败: {:?}", err);
            return (StatusCode::BAD_REQUEST, "读取请求体失败").into_response();
        }
    };

    // 将字节转换为UTF-8字符串
    let text_content = match String::from_utf8(bytes.to_vec()) {
        Ok(text) => text,
        Err(err) => {
            error!("请求体不是有效的UTF-8文本: {:?}", err);
            return (StatusCode::BAD_REQUEST, "请求体不是有效的UTF-8文本").into_response();
        }
    };

    // 更新剪贴板 - 在此作用域内完成，避免跨await持有MutexGuard
    {
        let mut clipboard = state.internal_clipboard.lock().unwrap();
        
        if let Some(data) = clipboard.as_mut() {
            data.update(text_content.clone());
        } else {
            *clipboard = Some(ClipboardData::new(text_content.clone()));
        }
    }
    
    // 记录日志 - 现在MutexGuard已经被释放
    log_clipboard_content(&state, &text_content, "PASTE", real_ip).await;
    
    info!("已从客户端 {} 接收剪贴板内容", real_ip);
    
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
    State(state): State<AppState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // 获取真实客户端IP
    let real_ip = get_real_ip(&headers, socket_addr);
    
    // 在局部作用域内获取内容的副本，避免MutexGuard跨越await
    let content_option = {
        let clipboard = state.internal_clipboard.lock().unwrap();
        
        match clipboard.as_ref() {
            Some(data) => Some(data.content.clone()),
            None => None,
        }
    };

    // 根据剪贴板内容生成响应
    match content_option {
        Some(content) => {
            // 在MutexGuard释放后记录日志
            log_clipboard_content(&state, &content, "COPY", real_ip).await;
            info!("将剪贴板内容发送给客户端: {}", real_ip);
            
            // 创建一个纯文本响应
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(content)
                .unwrap()
                .into_response()
        },
        None => {
            info!("剪贴板为空或已过期，客户端: {}", real_ip);
            
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

// 处理表单提交
async fn web_paste_handler(
    State(state): State<AppState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<PasteForm>,
) -> impl IntoResponse {
    // 获取真实客户端IP
    let real_ip = get_real_ip(&headers, socket_addr);
    
    // 在局部作用域内更新剪贴板，避免MutexGuard跨越await
    let content = form.content.clone();
    {
        let mut clipboard = state.internal_clipboard.lock().unwrap();
        
        if let Some(data) = clipboard.as_mut() {
            data.update(content.clone());
        } else {
            *clipboard = Some(ClipboardData::new(content.clone()));
        }
    }
    
    // 记录日志 - 确保在MutexGuard释放后执行
    log_clipboard_content(&state, &content, "WEB_PASTE", real_ip).await;
    
    info!("已从Web界面接收剪贴板内容，客户端: {}", real_ip);
    
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
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Html<String> {
    // 获取真实客户端IP
    let real_ip = get_real_ip(&headers, socket_addr);
    
    // 在局部作用域内获取内容的副本，避免MutexGuard跨越await
    let (content, status_message, has_content) = {
        let clipboard = state.internal_clipboard.lock().unwrap();
        
        match clipboard.as_ref() {
            Some(data) => {
                // 克隆内容，而不是在持有锁的情况下使用引用
                let content = data.content.clone();
                info!("从Web界面请求剪贴板内容，客户端: {}", real_ip);
                (content, "加载剪贴板内容完成", true)
            },
            None => {
                info!("剪贴板为空或已过期 (Web界面请求)，客户端: {}", real_ip);
                (String::new(), "剪贴板内容为空或已过期", false)
            }
        }
    };
    
    // 记录日志 - 现在MutexGuard已经被释放
    if has_content {
        log_clipboard_content(&state, &content, "WEB_COPY", real_ip).await;
    }
    
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
