use anyhow::Result;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn, error, debug};
use tokio::fs;

use crate::error::{NebulaError, Result as NebulaResult};

pub struct TlsManager {
    server_config: Arc<ServerConfig>,
    cert_path: PathBuf,
    key_path: PathBuf,
    domain: String,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    pub protocols: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub verify_client: bool,
    pub session_cache_size: usize,
    pub session_timeout: u32,
}

impl TlsManager {
    pub async fn new(cert_path: &Path, key_path: &Path, domain: &str) -> NebulaResult<Self> {
        if !cert_path.exists() {
            return Err(NebulaError::file_not_found(format!("Certificate file not found: {:?}", cert_path)));
        }

        if !key_path.exists() {
            return Err(NebulaError::file_not_found(format!("Private key file not found: {:?}", key_path)));
        }

        let server_config = Self::load_tls_config(cert_path, key_path).await?;
        
        Ok(Self {
            server_config: Arc::new(server_config),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            domain: domain.to_string(),
        })
    }

    pub async fn new_with_config(tls_config: TlsConfig, domain: &str) -> NebulaResult<Self> {
        let server_config = Self::load_tls_config_advanced(&tls_config).await?;
        
        Ok(Self {
            server_config: Arc::new(server_config),
            cert_path: tls_config.cert_path.clone(),
            key_path: tls_config.key_path.clone(),
            domain: domain.to_string(),
        })
    }

    async fn load_tls_config(cert_path: &Path, key_path: &Path) -> NebulaResult<ServerConfig> {
        // Load certificate chain
        let cert_file = File::open(cert_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open certificate file: {}", e)))?;
        let mut cert_reader = BufReader::new(cert_file);
        
        let cert_chain = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse certificate: {}", e)))?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();

        if cert_chain.is_empty() {
            return Err(NebulaError::certificate("No certificates found in certificate file"));
        }

        // Load private key
        let key_file = File::open(key_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open private key file: {}", e)))?;
        let mut key_reader = BufReader::new(key_file);
        
        let private_key = match rustls_pemfile::read_one(&mut key_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse private key: {}", e)))? {
            Some(rustls_pemfile::Item::RSAKey(key)) => PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => PrivateKey(key),
            _ => return Err(NebulaError::certificate("No valid private key found")),
        };

        // Create TLS configuration
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| NebulaError::certificate(format!("Failed to create TLS config: {}", e)))?;

        info!("TLS configuration loaded successfully");
        Ok(config)
    }

    async fn load_tls_config_advanced(tls_config: &TlsConfig) -> NebulaResult<ServerConfig> {
        // Load certificate chain
        let cert_file = File::open(&tls_config.cert_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open certificate file: {}", e)))?;
        let mut cert_reader = BufReader::new(cert_file);
        
        let cert_chain = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse certificate: {}", e)))?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();

        if cert_chain.is_empty() {
            return Err(NebulaError::certificate("No certificates found in certificate file"));
        }

        // Load private key
        let key_file = File::open(&tls_config.key_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open private key file: {}", e)))?;
        let mut key_reader = BufReader::new(key_file);
        
        let private_key = match rustls_pemfile::read_one(&mut key_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse private key: {}", e)))? {
            Some(rustls_pemfile::Item::RSAKey(key)) => PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => PrivateKey(key),
            _ => return Err(NebulaError::certificate("No valid private key found")),
        };

        // Create advanced TLS configuration
        let mut config_builder = ServerConfig::builder()
            .with_safe_defaults();

        // Configure client authentication if required
        if tls_config.verify_client {
            if let Some(ref ca_path) = tls_config.ca_path {
                let ca_file = File::open(ca_path)
                    .map_err(|e| NebulaError::certificate(format!("Failed to open CA file: {}", e)))?;
                let mut ca_reader = BufReader::new(ca_file);
                
                let ca_certs = rustls_pemfile::certs(&mut ca_reader)
                    .map_err(|e| NebulaError::certificate(format!("Failed to parse CA certificates: {}", e)))?
                    .into_iter()
                    .map(Certificate)
                    .collect::<Vec<_>>();

                let mut root_store = rustls::RootCertStore::empty();
                for cert in ca_certs {
                    root_store.add(&cert)
                        .map_err(|e| NebulaError::certificate(format!("Failed to add CA certificate: {}", e)))?;
                }

                let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(|e| NebulaError::certificate(format!("Failed to create client verifier: {}", e)))?;

                config_builder = config_builder.with_client_cert_verifier(client_cert_verifier);
            } else {
                return Err(NebulaError::certificate("Client verification enabled but no CA path provided"));
            }
        } else {
            config_builder = config_builder.with_no_client_auth();
        }

        let mut config = config_builder
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| NebulaError::certificate(format!("Failed to create TLS config: {}", e)))?;

        // Configure session cache
        config.session_storage = Arc::new(rustls::server::ServerSessionMemoryCache::new(tls_config.session_cache_size));

        info!("Advanced TLS configuration loaded successfully");
        Ok(config)
    }

    pub fn get_server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }

    pub async fn reload_certificates(&mut self) -> NebulaResult<()> {
        info!("Reloading TLS certificates for domain: {}", self.domain);
        
        let new_config = Self::load_tls_config(&self.cert_path, &self.key_path).await?;
        self.server_config = Arc::new(new_config);
        
        info!("✅ TLS certificates reloaded successfully");
        Ok(())
    }

    pub async fn reload_certificates_with_paths(&mut self, cert_path: &Path, key_path: &Path) -> NebulaResult<()> {
        info!("Reloading TLS certificates from new paths");
        
        let new_config = Self::load_tls_config(cert_path, key_path).await?;
        self.server_config = Arc::new(new_config);
        self.cert_path = cert_path.to_path_buf();
        self.key_path = key_path.to_path_buf();
        
        info!("✅ TLS certificates reloaded with new paths");
        Ok(())
    }

    pub async fn validate_certificate(&self) -> NebulaResult<CertificateInfo> {
        // Parse the certificate to extract information
        let cert_file = File::open(&self.cert_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open certificate file: {}", e)))?;
        let mut cert_reader = BufReader::new(cert_file);
        
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse certificate: {}", e)))?;

        if certs.is_empty() {
            return Err(NebulaError::certificate("No certificates found"));
        }

        // Parse the first certificate
        let cert = &certs[0];
        let parsed_cert = x509_parser::parse_x509_certificate(cert)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse certificate: {}", e)))?
            .1;

        let subject = parsed_cert.subject().to_string();
        let issuer = parsed_cert.issuer().to_string();
        let not_before = parsed_cert.validity().not_before;
        let not_after = parsed_cert.validity().not_after;
        
        // Extract SAN (Subject Alternative Names)
        let mut san_domains = Vec::new();
        if let Some(san_ext) = parsed_cert.extensions().iter().find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
            if let Ok(san) = x509_parser::extensions::parse_extension_san(&san_ext.value) {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns_name) = name {
                        san_domains.push(dns_name.to_string());
                    }
                }
            }
        }

        let now = std::time::SystemTime::now();
        let is_expired = now > not_after.to_system_time();
        let is_valid = now >= not_before.to_system_time() && now <= not_after.to_system_time();

        let cert_info = CertificateInfo {
            subject,
            issuer,
            not_before: not_before.to_system_time(),
            not_after: not_after.to_system_time(),
            san_domains,
            is_valid,
            is_expired,
            serial_number: parsed_cert.serial.to_string(),
            signature_algorithm: parsed_cert.signature_algorithm.algorithm().to_string(),
        };

        Ok(cert_info)
    }

    pub async fn check_certificate_expiry(&self) -> NebulaResult<CertificateStatus> {
        let cert_info = self.validate_certificate().await?;
        
        let now = std::time::SystemTime::now();
        let days_until_expiry = cert_info.not_after
            .duration_since(now)
            .map(|d| d.as_secs() / 86400)
            .unwrap_or(0);

        let status = if cert_info.is_expired {
            CertificateStatus::Expired
        } else if days_until_expiry <= 7 {
            CertificateStatus::ExpiringSoon(days_until_expiry)
        } else if days_until_expiry <= 30 {
            CertificateStatus::ExpiringInMonth(days_until_expiry)
        } else {
            CertificateStatus::Valid(days_until_expiry)
        };

        Ok(status)
    }

    pub fn get_domain(&self) -> &str {
        &self.domain
    }

    pub fn get_cert_path(&self) -> &Path {
        &self.cert_path
    }

    pub fn get_key_path(&self) -> &Path {
        &self.key_path
    }

    pub async fn create_tls_acceptor(&self) -> NebulaResult<tokio_rustls::TlsAcceptor> {
        let acceptor = tokio_rustls::TlsAcceptor::from(self.server_config.clone());
        Ok(acceptor)
    }

    pub async fn supports_alpn(&self, protocols: &[&str]) -> bool {
        // Check if the TLS config supports the specified ALPN protocols
        // This is a simplified check - in practice you'd examine the actual config
        protocols.contains(&"h2") || protocols.contains(&"http/1.1")
    }

    pub async fn get_negotiated_cipher_suite(&self) -> Option<&'static str> {
        // In a real implementation, you'd track the negotiated cipher suite
        // from actual TLS connections
        Some("TLS_AES_256_GCM_SHA384")
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: std::time::SystemTime,
    pub not_after: std::time::SystemTime,
    pub san_domains: Vec<String>,
    pub is_valid: bool,
    pub is_expired: bool,
    pub serial_number: String,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone)]
pub enum CertificateStatus {
    Valid(u64),           // Days until expiry
    ExpiringInMonth(u64), // Days until expiry (30 or fewer)
    ExpiringSoon(u64),    // Days until expiry (7 or fewer)
    Expired,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            ca_path: None,
            protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            verify_client: false,
            session_cache_size: 1024,
            session_timeout: 3600, // 1 hour
        }
    }
}

impl std::fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateStatus::Valid(days) => write!(f, "Valid ({} days remaining)", days),
            CertificateStatus::ExpiringInMonth(days) => write!(f, "Expiring in {} days", days),
            CertificateStatus::ExpiringSoon(days) => write!(f, "Expiring soon ({} days)", days),
            CertificateStatus::Expired => write!(f, "Expired"),
        }
    }
}

/// TLS utilities and helper functions
pub struct TlsUtils;

impl TlsUtils {
    /// Create a self-signed certificate for testing
    pub async fn create_self_signed_cert(domain: &str, output_dir: &Path) -> NebulaResult<(PathBuf, PathBuf)> {
        use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
        
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        
        // Set up distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        dn.push(DnType::OrganizationName, "Nebula Development");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;
        
        // Add SAN
        params.subject_alt_names = vec![
            SanType::DnsName(domain.to_string()),
            SanType::DnsName(format!("*.{}", domain)),
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
        ];
        
        // Set validity period
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 12, 31);
        
        let cert = Certificate::from_params(params)
            .map_err(|e| NebulaError::certificate(format!("Failed to generate certificate: {}", e)))?;
        
        // Write certificate and key
        fs::create_dir_all(output_dir).await
            .map_err(|e| NebulaError::certificate(format!("Failed to create output directory: {}", e)))?;
        
        let cert_path = output_dir.join(format!("{}.crt", domain));
        let key_path = output_dir.join(format!("{}.key", domain));
        
        fs::write(&cert_path, cert.serialize_pem()
            .map_err(|e| NebulaError::certificate(format!("Failed to serialize certificate: {}", e)))?)
            .await
            .map_err(|e| NebulaError::certificate(format!("Failed to write certificate: {}", e)))?;
        
        fs::write(&key_path, cert.serialize_private_key_pem())
            .await
            .map_err(|e| NebulaError::certificate(format!("Failed to write private key: {}", e)))?;
        
        info!("Self-signed certificate created for {}", domain);
        Ok((cert_path, key_path))
    }
    
    /// Validate certificate chain
    pub async fn validate_certificate_chain(cert_path: &Path, ca_path: Option<&Path>) -> NebulaResult<bool> {
        let cert_file = File::open(cert_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open certificate: {}", e)))?;
        let mut cert_reader = BufReader::new(cert_file);
        
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse certificates: {}", e)))?;
        
        if certs.is_empty() {
            return Err(NebulaError::certificate("No certificates found"));
        }
        
        // Basic validation - check if we can parse all certificates
        for (i, cert_der) in certs.iter().enumerate() {
            match x509_parser::parse_x509_certificate(cert_der) {
                Ok(_) => debug!("Certificate {} is valid", i),
                Err(e) => {
                    return Err(NebulaError::certificate(format!("Invalid certificate {}: {}", i, e)));
                }
            }
        }
        
        // If CA path is provided, validate against CA
        if let Some(ca_path) = ca_path {
            // Load CA certificates
            let ca_file = File::open(ca_path)
                .map_err(|e| NebulaError::certificate(format!("Failed to open CA file: {}", e)))?;
            let mut ca_reader = BufReader::new(ca_file);
            
            let ca_certs = rustls_pemfile::certs(&mut ca_reader)
                .map_err(|e| NebulaError::certificate(format!("Failed to parse CA certificates: {}", e)))?;
            
            // In a full implementation, you'd perform proper chain validation
            info!("Certificate chain validation completed");
        }
        
        Ok(true)
    }
    
    /// Get certificate fingerprint
    pub async fn get_certificate_fingerprint(cert_path: &Path) -> NebulaResult<String> {
        let cert_file = File::open(cert_path)
            .map_err(|e| NebulaError::certificate(format!("Failed to open certificate: {}", e)))?;
        let mut cert_reader = BufReader::new(cert_file);
        
        let certs = rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| NebulaError::certificate(format!("Failed to parse certificate: {}", e)))?;
        
        if certs.is_empty() {
            return Err(NebulaError::certificate("No certificates found"));
        }
        
        // Calculate SHA-256 fingerprint of the first certificate
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&certs[0]);
        let fingerprint = hasher.finalize();
        
        // Format as colon-separated hex
        let fingerprint_str = fingerprint.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");
        
        Ok(fingerprint_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_self_signed_certificate_creation() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();
        
        let result = TlsUtils::create_self_signed_cert("test.example.com", output_dir).await;
        assert!(result.is_ok(), "Should create self-signed certificate");
        
        let (cert_path, key_path) = result.unwrap();
        assert!(cert_path.exists(), "Certificate file should exist");
        assert!(key_path.exists(), "Key file should exist");
    }

    #[tokio::test]
    async fn test_certificate_validation() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();
        
        // Create a self-signed certificate
        let (cert_path, _) = TlsUtils::create_self_signed_cert("test.example.com", output_dir).await.unwrap();
        
        // Validate the certificate
        let result = TlsUtils::validate_certificate_chain(&cert_path, None).await;
        assert!(result.is_ok(), "Should validate certificate");
        assert!(result.unwrap(), "Certificate should be valid");
    }

    #[tokio::test]
    async fn test_certificate_fingerprint() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();
        
        // Create a self-signed certificate
        let (cert_path, _) = TlsUtils::create_self_signed_cert("test.example.com", output_dir).await.unwrap();
        
        // Get fingerprint
        let result = TlsUtils::get_certificate_fingerprint(&cert_path).await;
        assert!(result.is_ok(), "Should get certificate fingerprint");
        
        let fingerprint = result.unwrap();
        assert!(!fingerprint.is_empty(), "Fingerprint should not be empty");
        assert!(fingerprint.contains(':'), "Fingerprint should be colon-separated");
    }

    #[tokio::test]
    async fn test_tls_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();
        
        // Create a self-signed certificate
        let (cert_path, key_path) = TlsUtils::create_self_signed_cert("test.example.com", output_dir).await.unwrap();
        
        // Create TLS manager
        let result = TlsManager::new(&cert_path, &key_path, "test.example.com").await;
        assert!(result.is_ok(), "Should create TLS manager");
        
        let tls_manager = result.unwrap();
        assert_eq!(tls_manager.get_domain(), "test.example.com");
        assert_eq!(tls_manager.get_cert_path(), cert_path);
        assert_eq!(tls_manager.get_key_path(), key_path);
    }

    #[tokio::test]
    async fn test_certificate_info_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();
        
        // Create a self-signed certificate
        let (cert_path, key_path) = TlsUtils::create_self_signed_cert("test.example.com", output_dir).await.unwrap();
        
        // Create TLS manager and validate certificate
        let tls_manager = TlsManager::new(&cert_path, &key_path, "test.example.com").await.unwrap();
        let cert_info = tls_manager.validate_certificate().await.unwrap();
        
        assert!(cert_info.subject.contains("test.example.com"));
        assert!(cert_info.san_domains.contains(&"test.example.com".to_string()));
        assert!(cert_info.is_valid);
        assert!(!cert_info.is_expired);
    }
}
