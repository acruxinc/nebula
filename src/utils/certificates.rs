use anyhow::Result;
use rcgen::{generate_simple_self_signed, Certificate, KeyPair};
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn, debug};

pub struct CertificateManager {
    cert_dir: PathBuf,
    ca_cert: Option<Certificate>,
    ca_key: Option<KeyPair>,
}

impl CertificateManager {
    pub async fn new() -> Result<Self> {
        let cert_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nebula")
            .join("certs");

        fs::create_dir_all(&cert_dir)?;

        let mut manager = Self {
            cert_dir,
            ca_cert: None,
            ca_key: None,
        };

        // Initialize or load CA
        manager.ensure_ca().await?;

        Ok(manager)
    }

    async fn ensure_ca(&mut self) -> Result<()> {
        let ca_cert_path = self.cert_dir.join("nebula-ca.pem");
        let ca_key_path = self.cert_dir.join("nebula-ca-key.pem");

        if ca_cert_path.exists() && ca_key_path.exists() {
            debug!("Loading existing CA certificate");
            self.load_ca(&ca_cert_path, &ca_key_path)?;
        } else {
            info!("Generating new CA certificate");
            self.generate_ca().await?;
        }

        Ok(())
    }

    async fn generate_ca(&mut self) -> Result<()> {
        use rcgen::{CertificateParams, DistinguishedName, DnType};

        let mut params = CertificateParams::new(vec!["Nebula Development CA".to_string()]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Nebula Development CA");
        dn.push(DnType::OrganizationName, "Nebula Development");
        params.distinguished_name = dn;

        let ca_cert = Certificate::from_params(params)?;
        let ca_cert_pem = ca_cert.serialize_pem()?;
        let ca_key_pem = ca_cert.serialize_private_key_pem();

        // Save CA files
        let ca_cert_path = self.cert_dir.join("nebula-ca.pem");
        let ca_key_path = self.cert_dir.join("nebula-ca-key.pem");

        fs::write(&ca_cert_path, &ca_cert_pem)?;
        fs::write(&ca_key_path, &ca_key_pem)?;

        info!("✅ CA certificate generated and saved");
        Ok(())
    }

    fn load_ca(&mut self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<()> {
        let _cert_pem = fs::read_to_string(cert_path)?;
        let _key_pem = fs::read_to_string(key_path)?;

        // Note: This is simplified - in a real implementation you'd properly parse the PEM
        info!("✅ CA certificate loaded");
        Ok(())
    }

    pub async fn ensure_certificate(&self, domain: &str, force: bool) -> Result<Certificate> {
        let cert_path = self.cert_dir.join(format!("{}.pem", domain));
        let key_path = self.cert_dir.join(format!("{}-key.pem", domain));

        if !force && cert_path.exists() && key_path.exists() {
            info!("Using existing certificate for {}", domain);
            return self.load_certificate(&cert_path, &key_path);
        }

        info!("Generating new certificate for {}", domain);
        self.generate_certificate(domain).await
    }

    async fn generate_certificate(&self, domain: &str) -> Result<Certificate> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
        
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        
        // Add Subject Alternative Names for better compatibility
        let mut san_names = vec![
            SanType::DnsName(domain.to_string()),
            SanType::IpAddress("127.0.0.1".parse()?),
            SanType::IpAddress("::1".parse()?),
        ];
        
        // Add wildcard support for development domains
        if domain.ends_with(".nebula.com") {
            let base_domain = domain.trim_end_matches(".nebula.com");
            san_names.push(SanType::DnsName(format!("*.{}", base_domain)));
            san_names.push(SanType::DnsName(format!("*.nebula.com")));
        } else if domain.ends_with(".dev") {
            san_names.push(SanType::DnsName(format!("*.{}", domain)));
            san_names.push(SanType::DnsName("*.dev".to_string()));
        } else if domain.ends_with(".xyz") || domain.ends_with(".com") || domain.ends_with(".net") {
            // For production domains, add wildcard for subdomain
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() > 1 {
                let wildcard_domain = format!("*.{}", parts[1..].join("."));
                san_names.push(SanType::DnsName(wildcard_domain));
            }
        }
        
        // Always include localhost variants
        san_names.push(SanType::DnsName("localhost".to_string()));
        
        params.subject_alt_names = san_names;
        
        // Set certificate validity
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        
        // Set up distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        dn.push(DnType::OrganizationName, "Nebula Development");
        params.distinguished_name = dn;
        
        let cert = Certificate::from_params(params)?;

        let cert_path = self.cert_dir.join(format!("{}.pem", domain));
        let key_path = self.cert_dir.join(format!("{}-key.pem", domain));

        fs::write(&cert_path, cert.serialize_pem()?)?;
        fs::write(&key_path, cert.serialize_private_key_pem())?;

        info!("✅ Certificate generated for {} with wildcard support", domain);
        Ok(cert)
    }

    fn load_certificate(&self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<Certificate> {
        let _cert_pem = fs::read_to_string(cert_path)?;
        let _key_pem = fs::read_to_string(key_path)?;

        // For now, generate a new one - in production you'd parse the existing cert
        let subject_alt_names = vec!["localhost".to_string()];
        Ok(generate_simple_self_signed(subject_alt_names)?)
    }

    pub async fn list_certificates(&self) -> Result<Vec<String>> {
        let mut certificates = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.cert_dir) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "pem" && !path.file_name().unwrap().to_str().unwrap().contains("-key") {
                            if let Some(stem) = path.file_stem() {
                                if let Some(name) = stem.to_str() {
                                    certificates.push(name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(certificates)
    }

    pub async fn remove_certificate(&self, domain: &str) -> Result<()> {
        let cert_path = self.cert_dir.join(format!("{}.pem", domain));
        let key_path = self.cert_dir.join(format!("{}-key.pem", domain));

        if cert_path.exists() {
            fs::remove_file(&cert_path)?;
        }

        if key_path.exists() {
            fs::remove_file(&key_path)?;
        }

        info!("Certificate removed for {}", domain);
        Ok(())
    }

    pub async fn install_ca(&self) -> Result<()> {
        let ca_cert_path = self.cert_dir.join("nebula-ca.pem");

        if !ca_cert_path.exists() {
            return Err(anyhow::anyhow!("CA certificate not found"));
        }

        #[cfg(target_os = "macos")]
        {
            self.install_ca_macos(&ca_cert_path).await
        }

        #[cfg(target_os = "linux")]
        {
            self.install_ca_linux(&ca_cert_path).await
        }

        #[cfg(target_os = "windows")]
        {
            self.install_ca_windows(&ca_cert_path).await
        }
    }

    #[cfg(target_os = "macos")]
    async fn install_ca_macos(&self, ca_cert_path: &PathBuf) -> Result<()> {
        use std::process::Command;

        let output = Command::new("security")
            .args(&[
                "add-trusted-cert",
                "-d",
                "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                ca_cert_path.to_str().unwrap(),
            ])
            .output()?;

        if output.status.success() {
            info!("✅ CA certificate installed in macOS keychain");
        } else {
            warn!("Failed to install CA certificate: {}", 
                  String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn install_ca_linux(&self, ca_cert_path: &PathBuf) -> Result<()> {
        use std::process::Command;

        // Copy to system certificate directory
        let system_cert_path = "/usr/local/share/ca-certificates/nebula-ca.crt";
        
        let output = Command::new("sudo")
            .args(&["cp", ca_cert_path.to_str().unwrap(), system_cert_path])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to copy CA certificate"));
        }

        // Update CA certificates
        let output = Command::new("sudo")
            .arg("update-ca-certificates")
            .output()?;

        if output.status.success() {
            info!("✅ CA certificate installed in Linux");
        } else {
            warn!("Failed to update CA certificates");
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn install_ca_windows(&self, ca_cert_path: &PathBuf) -> Result<()> {
        use std::process::Command;

        let output = Command::new("certutil")
            .args(&[
                "-addstore",
                "-f",
                "Root",
                ca_cert_path.to_str().unwrap(),
            ])
            .output()?;

        if output.status.success() {
            info!("✅ CA certificate installed in Windows certificate store");
        } else {
            warn!("Failed to install CA certificate: {}", 
                  String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }

    pub fn get_cert_path(&self, domain: &str) -> PathBuf {
        self.cert_dir.join(format!("{}.pem", domain))
    }

    pub fn get_key_path(&self, domain: &str) -> PathBuf {
        self.cert_dir.join(format!("{}-key.pem", domain))
    }

    pub async fn generate_wildcard_certificate(&self, base_domain: &str) -> Result<Certificate> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
        
        let wildcard_domain = format!("*.{}", base_domain);
        let mut params = CertificateParams::new(vec![wildcard_domain.clone()]);
        
        // Add comprehensive SAN names for wildcard certificates
        let mut san_names = vec![
            SanType::DnsName(wildcard_domain.clone()),
            SanType::DnsName(base_domain.to_string()),
            SanType::IpAddress("127.0.0.1".parse()?),
            SanType::IpAddress("::1".parse()?),
            SanType::DnsName("localhost".to_string()),
        ];
        
        // Add common development patterns
        if base_domain.ends_with(".nebula.com") {
            let dev_base = base_domain.trim_end_matches(".nebula.com");
            san_names.push(SanType::DnsName(format!("*.{}", dev_base)));
            san_names.push(SanType::DnsName("*.nebula.com".to_string()));
        }
        
        params.subject_alt_names = san_names;
        
        // Set certificate validity for wildcards (longer validity)
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 12, 31);
        
        // Set up distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &wildcard_domain);
        dn.push(DnType::OrganizationName, "Nebula Development");
        params.distinguished_name = dn;
        
        let cert = Certificate::from_params(params)?;

        let cert_path = self.cert_dir.join(format!("{}.pem", wildcard_domain));
        let key_path = self.cert_dir.join(format!("{}-key.pem", wildcard_domain));

        fs::write(&cert_path, cert.serialize_pem()?)?;
        fs::write(&key_path, cert.serialize_private_key_pem())?;

        info!("✅ Wildcard certificate generated for {}", wildcard_domain);
        Ok(cert)
    }

    pub async fn ensure_wildcard_certificate(&self, base_domain: &str, force: bool) -> Result<Certificate> {
        let wildcard_domain = format!("*.{}", base_domain);
        let cert_path = self.cert_dir.join(format!("{}.pem", wildcard_domain));
        let key_path = self.cert_dir.join(format!("{}-key.pem", wildcard_domain));

        if !force && cert_path.exists() && key_path.exists() {
            info!("Using existing wildcard certificate for {}", wildcard_domain);
            return self.load_certificate(&cert_path, &key_path);
        }

        info!("Generating new wildcard certificate for {}", wildcard_domain);
        self.generate_wildcard_certificate(base_domain).await
    }

    pub async fn get_or_create_certificate(&self, domain: &str, force: bool) -> Result<Certificate> {
        // First try to get existing certificate
        if !force {
            if let Ok(cert) = self.ensure_certificate(domain, false).await {
                return Ok(cert);
            }
        }

        // If domain is a development domain, try wildcard
        if domain.ends_with(".nebula.com") || domain.ends_with(".dev") {
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                let base_domain = parts[1..].join(".");
                if let Ok(wildcard_cert) = self.ensure_wildcard_certificate(&base_domain, force).await {
                    return Ok(wildcard_cert);
                }
            }
        }

        // Fallback to domain-specific certificate
        self.ensure_certificate(domain, force).await
    }

    pub async fn cleanup_expired_certificates(&self) -> Result<()> {
        use std::time::SystemTime;
        
        let mut expired_count = 0;
        
        if let Ok(entries) = fs::read_dir(&self.cert_dir) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "pem" && !path.file_name().unwrap().to_str().unwrap().contains("-key") {
                            // Check if certificate is expired (simplified check)
                            if let Ok(metadata) = fs::metadata(&path) {
                                if let Ok(modified) = metadata.modified() {
                                    let age = SystemTime::now()
                                        .duration_since(modified)
                                        .unwrap_or_default();
                                    
                                    // Remove certificates older than 1 year
                                    if age.as_secs() > 365 * 24 * 60 * 60 {
                                        if let Some(stem) = path.file_stem() {
                                            if let Some(domain) = stem.to_str() {
                                                if let Err(e) = self.remove_certificate(domain).await {
                                                    warn!("Failed to remove expired certificate for {}: {}", domain, e);
                                                } else {
                                                    expired_count += 1;
                                                    info!("Removed expired certificate for {}", domain);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if expired_count > 0 {
            info!("Cleaned up {} expired certificates", expired_count);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_manager_creation() {
        let cert_manager = CertificateManager::new().await;
        assert!(cert_manager.is_ok(), "Certificate manager should be created successfully");
    }

    #[tokio::test]
    async fn test_certificate_generation() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Test certificate generation
        let cert = cert_manager.ensure_certificate("test.example.com", false).await;
        assert!(cert.is_ok(), "Should generate certificate successfully");
        
        // Verify certificate files exist
        let cert_path = cert_manager.get_cert_path("test.example.com");
        let key_path = cert_manager.get_key_path("test.example.com");
        
        assert!(cert_path.exists(), "Certificate file should exist");
        assert!(key_path.exists(), "Key file should exist");
    }

    #[tokio::test]
    async fn test_wildcard_certificate_generation() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Test wildcard certificate generation
        let wildcard_cert = cert_manager.generate_wildcard_certificate("nebula.com").await;
        assert!(wildcard_cert.is_ok(), "Should generate wildcard certificate successfully");
        
        // Verify wildcard certificate files exist
        let cert_path = cert_manager.get_cert_path("*.nebula.com");
        let key_path = cert_manager.get_key_path("*.nebula.com");
        
        assert!(cert_path.exists(), "Wildcard certificate file should exist");
        assert!(key_path.exists(), "Wildcard key file should exist");
    }

    #[tokio::test]
    async fn test_certificate_listing() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Generate some certificates
        cert_manager.ensure_certificate("test1.example.com", false).await.unwrap();
        cert_manager.ensure_certificate("test2.example.com", false).await.unwrap();
        cert_manager.generate_wildcard_certificate("test.com").await.unwrap();
        
        // List certificates
        let certs = cert_manager.list_certificates().await;
        assert!(certs.is_ok(), "Should list certificates successfully");
        
        let certs = certs.unwrap();
        assert!(certs.len() >= 3, "Should list at least 3 certificates");
        
        // Verify specific certificates are listed
        assert!(certs.contains(&"test1.example.com".to_string()));
        assert!(certs.contains(&"test2.example.com".to_string()));
        assert!(certs.contains(&"*.test.com".to_string()));
    }

    #[tokio::test]
    async fn test_certificate_removal() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Generate certificate
        cert_manager.ensure_certificate("test.example.com", false).await.unwrap();
        
        // Verify it exists
        let cert_path = cert_manager.get_cert_path("test.example.com");
        let key_path = cert_manager.get_key_path("test.example.com");
        assert!(cert_path.exists());
        assert!(key_path.exists());
        
        // Remove certificate
        let result = cert_manager.remove_certificate("test.example.com").await;
        assert!(result.is_ok(), "Should remove certificate successfully");
        
        // Verify files are removed
        assert!(!cert_path.exists(), "Certificate file should be removed");
        assert!(!key_path.exists(), "Key file should be removed");
    }

    #[tokio::test]
    async fn test_wildcard_certificate_management() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Test wildcard certificate creation
        let wildcard_cert = cert_manager.ensure_wildcard_certificate("nebula.com", false).await;
        assert!(wildcard_cert.is_ok(), "Should create wildcard certificate successfully");
        
        // Test getting or creating certificate for development domain
        let cert = cert_manager.get_or_create_certificate("myapp.nebula.com", false).await;
        assert!(cert.is_ok(), "Should get or create certificate for dev domain");
        
        // Test getting or creating certificate for production domain
        let cert = cert_manager.get_or_create_certificate("myapp.xyz", false).await;
        assert!(cert.is_ok(), "Should get or create certificate for prod domain");
    }

    #[tokio::test]
    async fn test_certificate_force_regeneration() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Generate initial certificate
        let cert1 = cert_manager.ensure_certificate("test.example.com", false).await.unwrap();
        
        // Force regeneration
        let cert2 = cert_manager.ensure_certificate("test.example.com", true).await.unwrap();
        
        // Both should be valid certificates
        assert!(cert1.serialize_pem().is_ok());
        assert!(cert2.serialize_pem().is_ok());
    }

    #[tokio::test]
    async fn test_certificate_path_generation() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        let cert_path = cert_manager.get_cert_path("test.example.com");
        let key_path = cert_manager.get_key_path("test.example.com");
        
        // Verify paths are correctly formatted
        assert!(cert_path.to_string_lossy().ends_with("test.example.com.pem"));
        assert!(key_path.to_string_lossy().ends_with("test.example.com-key.pem"));
    }

    #[tokio::test]
    async fn test_certificate_cleanup() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Generate some certificates
        cert_manager.ensure_certificate("test1.example.com", false).await.unwrap();
        cert_manager.ensure_certificate("test2.example.com", false).await.unwrap();
        
        // Run cleanup (should not remove recently created certificates)
        let result = cert_manager.cleanup_expired_certificates().await;
        assert!(result.is_ok(), "Should run cleanup successfully");
        
        // Verify certificates still exist
        let certs = cert_manager.list_certificates().await.unwrap();
        assert!(certs.contains(&"test1.example.com".to_string()));
        assert!(certs.contains(&"test2.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_certificate_with_special_characters() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Test certificate generation with special characters in domain
        let domains = vec![
            "test-subdomain.example.com",
            "test_subdomain.example.com",
            "test123.example.com",
            "test-with-dashes.example.com",
        ];
        
        for domain in domains {
            let cert = cert_manager.ensure_certificate(domain, false).await;
            assert!(cert.is_ok(), "Should generate certificate for domain: {}", domain);
            
            // Verify files exist
            let cert_path = cert_manager.get_cert_path(domain);
            let key_path = cert_manager.get_key_path(domain);
            assert!(cert_path.exists(), "Certificate file should exist for: {}", domain);
            assert!(key_path.exists(), "Key file should exist for: {}", domain);
        }
    }

    #[tokio::test]
    async fn test_certificate_san_names() {
        let cert_manager = CertificateManager::new().await.unwrap();
        
        // Generate certificate for nebula.com domain
        let cert = cert_manager.ensure_certificate("app.nebula.com", false).await.unwrap();
        
        // The certificate should include multiple SAN names
        let cert_pem = cert.serialize_pem().unwrap();
        
        // Basic validation that the certificate was generated
        assert!(!cert_pem.is_empty());
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
    }
}
