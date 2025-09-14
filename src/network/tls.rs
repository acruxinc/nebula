use anyhow::Result;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub struct TlsManager {
    server_config: Arc<ServerConfig>,
}

impl TlsManager {
    pub async fn new(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let server_config = Self::load_tls_config(cert_path, key_path).await?;
        
        Ok(Self {
            server_config: Arc::new(server_config),
        })
    }

    async fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
        // Load certificate chain
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain = rustls_pemfile::certs(&mut cert_reader)?
            .into_iter()
            .map(Certificate)
            .collect();

        // Load private key
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let private_key = match rustls_pemfile::private_key(&mut key_reader)? {
            Some(key) => PrivateKey(key),
            None => return Err(anyhow::anyhow!("No private key found")),
        };

        // Create TLS configuration
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }

    pub fn get_server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }

    pub async fn reload_certificates(&mut self, cert_path: &Path, key_path: &Path) -> Result<()> {
        let new_config = Self::load_tls_config(cert_path, key_path).await?;
        self.server_config = Arc::new(new_config);
        Ok(())
    }
}
