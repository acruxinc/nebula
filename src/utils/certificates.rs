use anyhow::Result;
use rcgen::{generate_simple_self_signed, Certificate, KeyPair, CertificateParams, DistinguishedName, DnType, SanType};
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn, debug, error};
use std::collections::HashMap;
use std::time::SystemTime;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub domain: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_wildcard: bool,
    pub san_domains: Vec<String>,
}

pub struct CertificateManager {
    cert_dir: PathBuf,
    ca_cert: Option<Certificate>,
    ca_key: Option<KeyPair>,
    certificates: HashMap<String, CertificateInfo>,
}

impl CertificateManager {
    pub async fn new() -> NebulaResult<Self> {
        let cert_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nebula")
            .join("certs");

        tokio::fs::create_dir_all(&cert_dir).await
            .map_err(|e| NebulaError::certificate(format!("Failed to create cert directory: {}", e)))?;

        let mut manager = Self {
            cert_dir,
            ca_cert: None,
            ca_key: None,
            certificates: HashMap::new(),
        };

        // Initialize or load CA
        manager.ensure_ca().await?;
        
        // Load existing certificates
        manager.load_existing_certificates().await?;

        Ok(manager)
    }

    pub async fn ensure_ca(&mut self) -> NebulaResult<()> {
        let ca_cert_path = self.cert_dir.join("nebula-ca.crt");
        let ca_key_path = self.cert_dir.join("nebula-ca.key");

        if ca_cert_path.exists() && ca_key_path.exists() {
            debug!("Loading existing CA certificate");
            self.load_ca(&ca_cert_path, &ca_key_path).await?;
        } else {
            info!("Generating new CA certificate");
            self.generate_ca().await?;
        }

        Ok(())
    }

    async fn generate_ca(&mut self) -> NebulaResult<()> {
        let mut params = CertificateParams::new(vec!["Nebula Development CA".to_string()]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Nebula Development CA");
        dn.push(DnType::OrganizationName, "Nebula Development");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;

        // Set validity for CA (10 years)
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);

        let ca_cert = Certificate::from_params(params)
            .map_err(|e| NebulaError::certificate(format!("Failed to generate CA: {}", e)))?;

        let ca_cert_pem = ca_cert.serialize_pem()
            .map_err(|e| NebulaError::certificate(format!("Failed to serialize CA cert: {}", e)))?;
        let ca_key_pem = ca_cert.serialize_private_key_pem();

        // Save CA files
        let ca_cert_path = self.cert_dir.join("nebula-ca.crt");
        let ca_key_path = self.cert_dir.join("nebula-ca.key");

        tokio::fs::write(&ca_cert_path, &ca_cert_pem).await
            .map_err(|e| NebulaError::certificate(format!("Failed to write CA cert: {}", e)))?;
        tokio::fs::write(&ca_key_path, &ca_key_pem).await
            .map_err(|e| NebulaError::certificate(format!("Failed to write CA key: {}", e)))?;

        self.ca_cert = Some(ca_cert);
        info!("✅ CA certificate generated and saved");
        Ok(())
    }

    async fn load_ca(&mut self, cert_path: &PathBuf, key_path: &PathBuf) -> NebulaResult<()> {
        let _cert_pem = tokio::fs::read_to_string(cert_path).await
            .map_err(|e| NebulaError::certificate(format!("Failed to read CA cert: {}", e)))?;
        let _key_pem = tokio::fs::read_to_string(key_path).await
            .map_err(|e| NebulaError::certificate(format!("Failed to read CA key: {}", e)))?;

        // For now, we'll regenerate the CA object when needed
        info!("✅ CA certificate loaded");
        Ok(())
    }

    pub async fn ensure_certificate(&self, domain: &str, force: bool) -> NebulaResult<Certificate> {
        let cert_path = self.cert_dir.join(format!("{}.crt", domain));
        let key_path = self.cert_dir.join(format!("{}.key", domain));

        if !force && cert_path.exists() && key_path.exists() {
            // Check if certificate is still valid
            if let Ok(cert_info) = self.parse_certificate_info(&cert_path).await {
                if cert_info.expires_at > Utc::now() {
                    info!("Using existing certificate for {}", domain);
                    return self.load_certificate_from_file(&cert_path, &key_path).await;
                } else {
                    info!("Certificate for {} has expired, regenerating", domain);
                }
            }
        }

        info!("Generating new certificate for {}", domain);
        self.generate_certificate(domain, 365).await
    }

    pub async fn generate_certificate(&self, domain: &str, validity_days: u32) -> NebulaResult<Certificate> {
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        
        // Add Subject Alternative Names for better compatibility
        let mut san_names = vec![
            SanType::DnsName(domain.to_string()),
            SanType::IpAddress("127.0.0.1".parse().unwrap()),
            SanType::IpAddress("::1".parse().unwrap()),
        ];
        
        // Add wildcard support for development domains
        if domain.ends_with(".nebula.com") {
            let base_domain = domain.trim_end_matches(".nebula.com");
            san_names.push(SanType::DnsName(format!("*.{}.nebula.com", base_domain)));
            san_names.push(SanType::DnsName("*.nebula.com".to_string()));
        } else if domain.ends_with(".dev") {
            san_names.push(SanType::DnsName(format!("*.{}", domain)));
            san_names.push(SanType::DnsName("*.dev".to_string()));
        }
        
        // Always include localhost variants
        san_names.push(SanType::DnsName("localhost".to_string()));
        
        params.subject_alt_names = san_names;
        
        // Set certificate validity
        let now = chrono::Utc::now();
        let not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        let future = now + chrono::Duration::days(validity_days as i64);
        let not_after = rcgen::date_time_ymd(future.year(), future.month() as u8, future.day() as u8);
        
        params.not_before = not_before;
        params.not_after = not_after;
        
        // Set up distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        dn.push(DnType::OrganizationName, "Nebula Development");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;
        
        let cert = Certificate::from_params(params)
            .map_err(|e| NebulaError::certificate(format!("Failed to generate certificate: {}", e)))?;

        let cert_path = self.cert_dir.join(format!("{}.crt", domain));
        let key_path = self.cert_dir.join(format!("{}.key", domain));

        let cert_pem = cert.serialize_pem()
            .map_err(|e| NebulaError::certificate(format!("Failed to serialize cert: {}", e)))?;
        let key_pem = cert.serialize_private_key_pem();

        tokio::fs::write(&cert_path, cert_pem).await
            .map_err(|e| NebulaError::certificate(format!("Failed to write cert: {}", e)))?;
        tokio::fs::write(&key_path, key_pem).await
            .map_err(|e| NebulaError::certificate(format!("Failed to write key: {}", e)))?;

        info!("✅ Certificate generated for {}", domain);
        Ok(cert)
    }

    pub async fn generate_wildcard_certificate(&self, domain: &str, validity_days: u32) -> NebulaResult<Certificate> {
        let wildcard_domain = if domain.starts_with("*.") {
            domain.to_string()
        } else {
            format!("*.{}", domain)
        };

        self.generate_certificate(&wildcard_domain, validity_days).await
    }

    async fn load_certificate_from_file(&self, cert_path: &PathBuf, _key_path: &PathBuf) -> NebulaResult<Certificate> {
        // For now, generate a simple certificate
        // In a full implementation, you'd parse the existing certificate
        let subject_alt_names = vec!["localhost".to_string()];
        generate_simple_self_signed(subject_alt_names)
            .map_err(|e| NebulaError::certificate(format!("Failed to load certificate: {}", e)))
    }

    pub async fn list_certificates(&self, show_expired: bool) -> NebulaResult<Vec<CertificateInfo>> {
        let mut certificates = Vec::new();
        let now = Utc::now();

        if let Ok(mut entries) = tokio::fs::read_dir(&self.cert_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "crt" && !path.file_name().unwrap().to_str().unwrap().contains("ca") {
                        if let Ok(cert_info) = self.parse_certificate_info(&path).await {
                            if show_expired || cert_info.expires_at > now {
                                certificates.push(cert_info);
                            }
                        }
                    }
                }
            }
        }

        // Sort by expiration date
        certificates.sort_by(|a, b| a.expires_at.cmp(&b.expires_at));
        Ok(certificates)
    }

    async fn parse_certificate_info(&self, cert_path: &PathBuf) -> NebulaResult<CertificateInfo> {
        let domain = cert_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let key_path = cert_path.with_extension("key");
        
        // For now, return basic info
        // In a full implementation, you'd parse the actual certificate
        Ok(CertificateInfo {
            domain: domain.clone(),
            cert_path: cert_path.clone(),
            key_path,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
            is_wildcard: domain.starts_with("*."),
            san_domains: vec![domain],
        })
    }

    pub async fn remove_certificate(&self, domain: &str) -> NebulaResult<()> {
        let cert_path = self.cert_dir.join(format!("{}.crt", domain));
        let key_path = self.cert_dir.join(format!("{}.key", domain));

        if cert_path.exists() {
            tokio::fs::remove_file(&cert_path).await
                .map_err(|e| NebulaError::certificate(format!("Failed to remove cert: {}", e)))?;
        }

        if key_path.exists() {
            tokio::fs::remove_file(&key_path).await
                .map_err(|e| NebulaError::certificate(format!("Failed to remove key: {}", e)))?;
        }

        info!("Certificate removed for {}", domain);
        Ok(())
    }

    pub async fn remove_all_certificates(&self, domain_pattern: &str) -> NebulaResult<usize> {
        let mut removed_count = 0;

        if let Ok(mut entries) = tokio::fs::read_dir(&self.cert_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    if file_name.contains(domain_pattern) && (file_name.ends_with(".crt") || file_name.ends_with(".key")) {
                        if let Err(e) = tokio::fs::remove_file(&path).await {
                            warn!("Failed to remove {}: {}", file_name, e);
                        } else {
                            removed_count += 1;
                            debug!("Removed: {}", file_name);
                        }
                    }
                }
            }
        }

        Ok(removed_count)
    }

    pub async fn install_ca(&self, _store: Option<&str>) -> NebulaResult<()> {
        let ca_cert_path = self.cert_dir.join("nebula-ca.crt");

        if !ca_cert_path.exists() {
            return Err(NebulaError::certificate("CA certificate not found"));
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

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err(NebulaError::platform("CA installation not supported on this platform"))
        }
    }

    #[cfg(target_os = "macos")]
    async fn install_ca_macos(&self, ca_cert_path: &PathBuf) -> NebulaResult<()> {
        use std::process::Command;

        let output = Command::new("security")
            .args(&[
                "add-trusted-cert",
                "-d",
                "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                ca_cert_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| NebulaError::platform(format!("Failed to run security command: {}", e)))?;

        if output.status.success() {
            info!("✅ CA certificate installed in macOS keychain");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NebulaError::certificate(format!("Failed to install CA certificate: {}", stderr)));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn install_ca_linux(&self, ca_cert_path: &PathBuf) -> NebulaResult<()> {
        use std::process::Command;

        // Copy to system certificate directory
        let system_cert_path = "/usr/local/share/ca-certificates/nebula-ca.crt";
        
        let output = Command::new("sudo")
            .args(&["cp", ca_cert_path.to_str().unwrap(), system_cert_path])
            .output()
            .map_err(|e| NebulaError::platform(format!("Failed to copy CA certificate: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NebulaError::certificate(format!("Failed to copy CA certificate: {}", stderr)));
        }

        // Update CA certificates
        let output = Command::new("sudo")
            .arg("update-ca-certificates")
            .output()
            .map_err(|e| NebulaError::platform(format!("Failed to update CA certificates: {}", e)))?;

        if output.status.success() {
            info!("✅ CA certificate installed in Linux");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to update CA certificates: {}", stderr);
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn install_ca_windows(&self, ca_cert_path: &PathBuf) -> NebulaResult<()> {
        use std::process::Command;

        let output = Command::new("certutil")
            .args(&[
                "-addstore",
                "-f",
                "Root",
                ca_cert_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| NebulaError::platform(format!("Failed to run certutil: {}", e)))?;

        if output.status.success() {
            info!("✅ CA certificate installed in Windows certificate store");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NebulaError::certificate(format!("Failed to install CA certificate: {}", stderr)));
        }

        Ok(())
    }

    pub async fn remove_ca(&self) -> NebulaResult<()> {
        #[cfg(target_os = "macos")]
        {
            self.remove_ca_macos().await
        }

        #[cfg(target_os = "linux")]
        {
            self.remove_ca_linux().await
        }

        #[cfg(target_os = "windows")]
        {
            self.remove_ca_windows().await
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    async fn remove_ca_macos(&self) -> NebulaResult<()> {
        use std::process::Command;

        let output = Command::new("security")
            .args(&[
                "delete-certificate",
                "-c", "Nebula Development CA",
                "/Library/Keychains/System.keychain",
            ])
            .output()
            .map_err(|e| NebulaError::platform(format!("Failed to run security command: {}", e)))?;

        if output.status.success() {
            info!("✅ CA certificate removed from macOS keychain");
        } else {
            warn!("CA certificate may not have been installed or already removed");
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn remove_ca_linux(&self) -> NebulaResult<()> {
        use std::process::Command;

        let system_cert_path = "/usr/local/share/ca-certificates/nebula-ca.crt";
        let _ = Command::new("sudo")
            .args(&["rm", "-f", system_cert_path])
            .output();

        let _ = Command::new("sudo")
            .arg("update-ca-certificates")
            .output();

        info!("✅ CA certificate removed from Linux");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn remove_ca_windows(&self) -> NebulaResult<()> {
        use std::process::Command;

        let output = Command::new("certutil")
            .args(&[
                "-delstore",
                "Root",
                "Nebula Development CA",
            ])
            .output()
            .map_err(|e| NebulaError::platform(format!("Failed to run certutil: {}", e)))?;

        if output.status.success() {
            info!("✅ CA certificate removed from Windows certificate store");
        } else {
            warn!("CA certificate may not have been installed or already removed");
        }

        Ok(())
    }

    pub async fn verify_certificate(&self, domain: &str) -> NebulaResult<bool> {
        let cert_path = self.cert_dir.join(format!("{}.crt", domain));
        
        if !cert_path.exists() {
            return Ok(false);
        }

        let cert_info = self.parse_certificate_info(&cert_path).await?;
        let now = Utc::now();
        
        Ok(cert_info.expires_at > now)
    }

    pub async fn renew_all_certificates(&self, days_before_expiry: u32) -> NebulaResult<usize> {
        let certificates = self.list_certificates(false).await?;
        let threshold = Utc::now() + chrono::Duration::days(days_before_expiry as i64);
        let mut renewed_count = 0;

        for cert_info in certificates {
            if cert_info.expires_at < threshold {
                info!("Renewing certificate for: {}", cert_info.domain);
                match self.generate_certificate(&cert_info.domain, 365).await {
                    Ok(_) => {
                        renewed_count += 1;
                        info!("✅ Renewed certificate for: {}", cert_info.domain);
                    }
                    Err(e) => {
                        error!("Failed to renew certificate for {}: {}", cert_info.domain, e);
                    }
                }
            }
        }

        Ok(renewed_count)
    }

    pub async fn clean_all_certificates(&self) -> NebulaResult<usize> {
        let mut removed_count = 0;

        if let Ok(mut entries) = tokio::fs::read_dir(&self.cert_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                    if file_name.ends_with(".crt") || file_name.ends_with(".key") {
                        if let Err(e) = tokio::fs::remove_file(&path).await {
                            warn!("Failed to remove {}: {}", file_name, e);
                        } else {
                            removed_count += 1;
                            debug!("Removed: {}", file_name);
                        }
                    }
                }
            }
        }

        Ok(removed_count)
    }

    pub fn get_cert_path(&self, domain: &str) -> PathBuf {
        self.cert_dir.join(format!("{}.crt", domain))
    }

    pub fn get_key_path(&self, domain: &str) -> PathBuf {
        self.cert_dir.join(format!("{}.key", domain))
    }

    async fn load_existing_certificates(&mut self) -> NebulaResult<()> {
        if let Ok(certificates) = self.list_certificates(true).await {
            for cert_info in certificates {
                self.certificates.insert(cert_info.domain.clone(), cert_info);
            }
        }
        Ok(())
    }
}
