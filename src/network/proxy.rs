use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, Uri};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::utils::certificates::CertificateManager;

pub struct ReverseProxy {
    https_port: u16,
    http_port: u16,
    domain: String,
    cert_manager: Arc<CertificateManager>,
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl ReverseProxy {
    pub async fn new(
        https_port: u16,
        http_port: u16,
        domain: &str,
        cert_manager: Arc<CertificateManager>,
    ) -> Result<Self> {
        Ok(Self {
            https_port,
            http_port,
            domain: domain.to_string(),
            cert_manager,
            server_handle: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!(
            "Starting reverse proxy: https://{}:{} -> http://127.0.0.1:{}",
            self.domain, self.https_port, self.http_port
        );

        let http_port = self.http_port;
        let client = Client::new();

        let make_svc = make_service_fn(move |_conn| {
            let client = client.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    proxy_request(req, client.clone(), http_port)
                }))
            }
        });

        let addr = SocketAddr::from(([127, 0, 0, 1], self.https_port));
        let server = Server::bind(&addr).serve(make_svc);

        let handle = tokio::spawn(async move {
            if let Err(e) = server.await {
                warn!("Reverse proxy server error: {}", e);
            }
        });

        *self.server_handle.write().await = Some(handle);

        info!("✅ Reverse proxy started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping reverse proxy...");
        
        if let Some(handle) = self.server_handle.write().await.take() {
            handle.abort();
        }

        Ok(())
    }
}

async fn proxy_request(
    mut req: Request<Body>,
    client: Client<hyper::client::HttpConnector>,
    target_port: u16,
) -> Result<Response<Body>, Infallible> {
    let uri_string = format!(
        "http://127.0.0.1:{}{}",
        target_port,
        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
    );

    let uri = uri_string.parse::<Uri>().unwrap();
    *req.uri_mut() = uri;

    match client.request(req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            warn!("Proxy request failed: {}", e);
            Ok(Response::builder()
                .status(502)
                .body(Body::from("Bad Gateway"))
                .unwrap())
        }
    }
}
