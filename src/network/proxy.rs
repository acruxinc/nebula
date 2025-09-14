use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, Uri, StatusCode, HeaderMap};
use hyper::header::{HeaderName, HeaderValue, HOST, CONTENT_ENCODING, TRANSFER_ENCODING};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tracing::{info, warn, debug, error};
use std::collections::HashMap;

use crate::utils::CertificateManager;
use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Clone)]
pub struct ReverseProxy {
    https_port: u16,
    http_port: u16,
    target_port: u16,
    domain: String,
    cert_manager: Arc<CertificateManager>,
    config: ProxyConfig,
    metrics: Arc<RwLock<ProxyMetrics>>,
    health_status: Arc<RwLock<ProxyHealth>>,
    server_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    is_running: Arc<RwLock<bool>>,
    middleware: Arc<Vec<Box<dyn ProxyMiddleware + Send + Sync>>>,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub enable_compression: bool,
    pub enable_caching: bool,
    pub cache_ttl: Duration,
    pub max_body_size: u64,
    pub timeout: Duration,
    pub retry_attempts: u32,
    pub retry_delay: Duration,
    pub enable_websockets: bool,
    pub cors_enabled: bool,
    pub cors_origins: Vec<String>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

#[derive(Debug, Clone)]
pub struct ProxyMetrics {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_error: u64,
    pub response_time_ms: u64,
    pub bytes_transferred: u64,
    pub active_connections: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rate_limited: u64,
}

#[derive(Debug, Clone)]
pub struct ProxyHealth {
    pub is_healthy: bool,
    pub last_check: Option<Instant>,
    pub target_healthy: bool,
    pub error_rate: f64,
    pub avg_response_time: Duration,
}

pub trait ProxyMiddleware {
    fn name(&self) -> &str;
    fn process_request(&self, req: &mut Request<Body>) -> Result<(), NebulaError>;
    fn process_response(&self, res: &mut Response<Body>) -> Result<(), NebulaError>;
}

pub struct CompressionMiddleware;
pub struct CorsMiddleware {
    origins: Vec<String>,
}
pub struct RateLimitMiddleware {
    limit: RateLimit,
    client_counts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
}

impl ReverseProxy {
    pub async fn new(
        https_port: u16,
        http_port: u16,
        domain: &str,
        cert_manager: Arc<CertificateManager>,
    ) -> NebulaResult<Self> {
        // Determine target port (where the actual application is running)
        let target_port = if http_port == 3000 { 3001 } else { http_port + 1 };

        let config = ProxyConfig::default();
        let metrics = Arc::new(RwLock::new(ProxyMetrics::default()));
        let health_status = Arc::new(RwLock::new(ProxyHealth::default()));

        let mut middleware: Vec<Box<dyn ProxyMiddleware + Send + Sync>> = Vec::new();
        
        if config.enable_compression {
            middleware.push(Box::new(CompressionMiddleware));
        }
        
        if config.cors_enabled {
            middleware.push(Box::new(CorsMiddleware {
                origins: config.cors_origins.clone(),
            }));
        }
        
        if let Some(rate_limit) = config.rate_limit.clone() {
            middleware.push(Box::new(RateLimitMiddleware {
                limit: rate_limit,
                client_counts: Arc::new(RwLock::new(HashMap::new())),
            }));
        }

        Ok(Self {
            https_port,
            http_port,
            target_port,
            domain: domain.to_string(),
            cert_manager,
            config,
            metrics,
            health_status,
            server_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(RwLock::new(false)),
            middleware: Arc::new(middleware),
        })
    }

    pub async fn start(&self) -> NebulaResult<()> {
        {
            let mut running = self.is_running.write().await;
            if *running {
                return Err(NebulaError::already_exists("Reverse proxy is already running"));
            }
            *running = true;
        }

        info!(
            "Starting reverse proxy: https://{}:{} -> http://127.0.0.1:{}",
            self.domain, self.https_port, self.target_port
        );

        let mut handles = Vec::new();

        // Start HTTP server (redirects to HTTPS)
        let http_handle = self.start_http_server().await?;
        handles.push(http_handle);

        // Start HTTPS server
        let https_handle = self.start_https_server().await?;
        handles.push(https_handle);

        // Start health monitoring
        let health_handle = self.start_health_monitoring().await?;
        handles.push(health_handle);

        // Start metrics collection
        let metrics_handle = self.start_metrics_collection().await?;
        handles.push(metrics_handle);

        {
            let mut server_handles = self.server_handles.lock().await;
            *server_handles = handles;
        }

        info!("✅ Reverse proxy started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> NebulaResult<()> {
        info!("Stopping reverse proxy...");

        {
            let mut running = self.is_running.write().await;
            *running = false;
        }

        // Stop all server handles
        {
            let mut handles = self.server_handles.lock().await;
            for handle in handles.drain(..) {
                handle.abort();
            }
        }

        info!("✅ Reverse proxy stopped");
        Ok(())
    }

    pub async fn is_healthy(&self) -> bool {
        let health = self.health_status.read().await;
        health.is_healthy && health.target_healthy
    }

    pub async fn get_metrics(&self) -> ProxyMetrics {
        self.metrics.read().await.clone()
    }

    async fn start_http_server(&self) -> NebulaResult<tokio::task::JoinHandle<()>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.http_port));
        let https_port = self.https_port;
        let domain = self.domain.clone();

        let make_svc = make_service_fn(move |_conn| {
            let domain = domain.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    redirect_to_https(req, domain.clone(), https_port)
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        let graceful = server.with_graceful_shutdown(self.shutdown_signal());

        let handle = tokio::spawn(async move {
            if let Err(e) = graceful.await {
                error!("HTTP server error: {}", e);
            }
        });

        info!("HTTP server started on {}", addr);
        Ok(handle)
    }

    async fn start_https_server(&self) -> NebulaResult<tokio::task::JoinHandle<()>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.https_port));
        let target_port = self.target_port;
        let metrics = self.metrics.clone();
        let middleware = self.middleware.clone();
        let config = self.config.clone();

        let make_svc = make_service_fn(move |_conn| {
            let metrics = metrics.clone();
            let middleware = middleware.clone();
            let config = config.clone();
            
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_proxy_request(req, target_port, metrics.clone(), middleware.clone(), config.clone())
                }))
            }
        });

        // TODO: Add TLS configuration using rustls
        // For now, we'll use HTTP for the HTTPS port (this should be fixed)
        let server = Server::bind(&addr).serve(make_svc);
        let graceful = server.with_graceful_shutdown(self.shutdown_signal());

        let handle = tokio::spawn(async move {
            if let Err(e) = graceful.await {
                error!("HTTPS server error: {}", e);
            }
        });

        info!("HTTPS server started on {}", addr);
        Ok(handle)
    }

    async fn start_health_monitoring(&self) -> NebulaResult<tokio::task::JoinHandle<()>> {
        let health_status = self.health_status.clone();
        let target_port = self.target_port;
        let is_running = self.is_running.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            let client = Client::new();

            loop {
                interval.tick().await;

                if !*is_running.read().await {
                    break;
                }

                let start = Instant::now();
                let target_healthy = match client.get(format!("http://127.0.0.1:{}/", target_port).parse::<Uri>().unwrap()).await {
                    Ok(response) => response.status().is_success(),
                    Err(_) => false,
                };
                let response_time = start.elapsed();

                {
                    let mut health = health_status.write().await;
                    health.last_check = Some(Instant::now());
                    health.target_healthy = target_healthy;
                    health.avg_response_time = response_time;
                    health.is_healthy = target_healthy; // Simplified health check
                }

                debug!("Health check: target_healthy={}, response_time={:?}", target_healthy, response_time);
            }
        });

        Ok(handle)
    }

    async fn start_metrics_collection(&self) -> NebulaResult<tokio::task::JoinHandle<()>> {
        let metrics = self.metrics.clone();
        let is_running = self.is_running.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                if !*is_running.read().await {
                    break;
                }

                // Reset rate counters and perform cleanup
                {
                    let mut metrics = metrics.write().await;
                    // Log metrics or send to monitoring system
                    debug!("Proxy metrics: {:?}", *metrics);
                }
            }
        });

        Ok(handle)
    }

    async fn shutdown_signal(&self) {
        loop {
            if !*self.is_running.read().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn redirect_to_https(
    req: Request<Body>,
    domain: String,
    https_port: u16,
) -> Result<Response<Body>, Infallible> {
    let https_url = if https_port == 443 {
        format!("https://{}{}", domain, req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/"))
    } else {
        format!("https://{}:{}{}", domain, https_port, req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/"))
    };

    let response = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("Location", https_url)
        .header("Cache-Control", "no-cache")
        .body(Body::from("Redirecting to HTTPS"))
        .unwrap();

    Ok(response)
}

async fn handle_proxy_request(
    mut req: Request<Body>,
    target_port: u16,
    metrics: Arc<RwLock<ProxyMetrics>>,
    middleware: Arc<Vec<Box<dyn ProxyMiddleware + Send + Sync>>>,
    config: ProxyConfig,
) -> Result<Response<Body>, Infallible> {
    let start_time = Instant::now();
    
    // Update metrics
    {
        let mut m = metrics.write().await;
        m.requests_total += 1;
        m.active_connections += 1;
    }

    // Process request through middleware
    for middleware_item in middleware.iter() {
        if let Err(e) = middleware_item.process_request(&mut req) {
            warn!("Middleware {} failed: {}", middleware_item.name(), e);
            return Ok(create_error_response(StatusCode::BAD_REQUEST, &e.to_string()));
        }
    }

    // Create target URI
    let target_uri = match create_target_uri(&req, target_port) {
        Ok(uri) => uri,
        Err(e) => {
            error!("Failed to create target URI: {}", e);
            return Ok(create_error_response(StatusCode::BAD_GATEWAY, "Invalid target"));
        }
    };

    // Update request URI
    *req.uri_mut() = target_uri;

    // Remove hop-by-hop headers
    remove_hop_by_hop_headers(req.headers_mut());

    // Create HTTP client with timeout
    let client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .build_http();

    // Forward request with retry logic
    let mut response = None;
    for attempt in 1..=config.retry_attempts {
        match tokio::time::timeout(config.timeout, client.request(req.clone())).await {
            Ok(Ok(res)) => {
                response = Some(res);
                break;
            }
            Ok(Err(e)) => {
                warn!("Request failed (attempt {}): {}", attempt, e);
                if attempt < config.retry_attempts {
                    tokio::time::sleep(config.retry_delay).await;
                }
            }
            Err(_) => {
                warn!("Request timeout (attempt {})", attempt);
                if attempt < config.retry_attempts {
                    tokio::time::sleep(config.retry_delay).await;
                }
            }
        }
    }

    let mut final_response = match response {
        Some(mut res) => {
            // Process response through middleware
            for middleware_item in middleware.iter() {
                if let Err(e) = middleware_item.process_response(&mut res) {
                    warn!("Response middleware {} failed: {}", middleware_item.name(), e);
                }
            }

            // Remove hop-by-hop headers from response
            remove_hop_by_hop_headers(res.headers_mut());

            // Add security headers
            add_security_headers(res.headers_mut());

            res
        }
        None => create_error_response(StatusCode::BAD_GATEWAY, "Service unavailable"),
    };

    // Update metrics
    let response_time = start_time.elapsed();
    {
        let mut m = metrics.write().await;
        m.active_connections -= 1;
        m.response_time_ms = response_time.as_millis() as u64;
        
        if final_response.status().is_success() {
            m.requests_success += 1;
        } else {
            m.requests_error += 1;
        }
    }

    Ok(final_response)
}

fn create_target_uri(req: &Request<Body>, target_port: u16) -> NebulaResult<Uri> {
    let path_and_query = req.uri().path_and_query()
        .map(|x| x.as_str())
        .unwrap_or("/");
    
    let target_url = format!("http://127.0.0.1:{}{}", target_port, path_and_query);
    
    target_url.parse()
        .map_err(|e| NebulaError::network(format!("Invalid target URI: {}", e)))
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    // Remove hop-by-hop headers as per RFC 7230
    let hop_by_hop_headers = [
        "connection",
        "keep-alive", 
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    for header in &hop_by_hop_headers {
        headers.remove(*header);
    }
}

fn add_security_headers(headers: &mut HeaderMap) {
    // Add security headers
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
}

fn create_error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(message.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("Internal server error")))
}

// Middleware implementations

impl ProxyMiddleware for CompressionMiddleware {
    fn name(&self) -> &str {
        "compression"
    }

    fn process_request(&self, _req: &mut Request<Body>) -> Result<(), NebulaError> {
        // Add Accept-Encoding header if not present
        if !_req.headers().contains_key("accept-encoding") {
            _req.headers_mut().insert(
                "accept-encoding",
                HeaderValue::from_static("gzip, deflate, br")
            );
        }
        Ok(())
    }

    fn process_response(&self, res: &mut Response<Body>) -> Result<(), NebulaError> {
        // Response compression would be implemented here
        // For now, just ensure we don't double-encode
        Ok(())
    }
}

impl ProxyMiddleware for CorsMiddleware {
    fn name(&self) -> &str {
        "cors"
    }

    fn process_request(&self, _req: &mut Request<Body>) -> Result<(), NebulaError> {
        Ok(())
    }

    fn process_response(&self, res: &mut Response<Body>) -> Result<(), NebulaError> {
        let headers = res.headers_mut();
        
        headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
        headers.insert("Access-Control-Allow-Methods", HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
        headers.insert("Access-Control-Allow-Headers", HeaderValue::from_static("Content-Type, Authorization"));
        headers.insert("Access-Control-Max-Age", HeaderValue::from_static("86400"));
        
        Ok(())
    }
}

impl ProxyMiddleware for RateLimitMiddleware {
    fn name(&self) -> &str {
        "rate_limit"
    }

    fn process_request(&self, req: &mut Request<Body>) -> Result<(), NebulaError> {
        // Extract client IP (simplified)
        let client_ip = "127.0.0.1"; // In real implementation, extract from headers or connection

        // Check rate limit (simplified implementation)
        // In production, you'd use a more sophisticated rate limiting algorithm
        
        Ok(())
    }

    fn process_response(&self, _res: &mut Response<Body>) -> Result<(), NebulaError> {
        Ok(())
    }
}

// Default implementations

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enable_compression: true,
            enable_caching: false,
            cache_ttl: Duration::from_secs(3600),
            max_body_size: 100 * 1024 * 1024, // 100MB
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
            retry_delay: Duration::from_millis(1000),
            enable_websockets: true,
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
            rate_limit: None,
        }
    }
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self {
            requests_total: 0,
            requests_success: 0,
            requests_error: 0,
            response_time_ms: 0,
            bytes_transferred: 0,
            active_connections: 0,
            cache_hits: 0,
            cache_misses: 0,
            rate_limited: 0,
        }
    }
}

impl Default for ProxyHealth {
    fn default() -> Self {
        Self {
            is_healthy: true,
            last_check: None,
            target_healthy: false,
            error_rate: 0.0,
            avg_response_time: Duration::from_millis(0),
        }
    }
}

impl Clone for ProxyMetrics {
    fn clone(&self) -> Self {
        Self {
            requests_total: self.requests_total,
            requests_success: self.requests_success,
            requests_error: self.requests_error,
            response_time_ms: self.response_time_ms,
            bytes_transferred: self.bytes_transferred,
            active_connections: self.active_connections,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            rate_limited: self.rate_limited,
        }
    }
}
