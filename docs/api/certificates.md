# Certificate API Reference

This document provides a comprehensive reference for Nebula's certificate management API, including TLS certificate generation, validation, and management.

## Certificate Manager

### CertificateManager

The main certificate management system.

```rust
pub struct CertificateManager {
    cert_dir: PathBuf,
    ca_cert: Option<Certificate>,
    ca_key: Option<PrivateKey>,
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
    config: TlsConfig,
}

impl CertificateManager {
    pub async fn new() -> Result<Self>;
    pub async fn new_with_config(config: TlsConfig) -> Result<Self>;
    pub async fn ensure_ca(&mut self) -> Result<()>;
    pub async fn generate_certificate(&mut self, domain: &str) -> Result<Certificate>;
    pub async fn generate_wildcard_certificate(&mut self, domain: &str) -> Result<Certificate>;
    pub async fn get_certificate(&self, domain: &str) -> Option<Certificate>;
    pub async fn remove_certificate(&mut self, domain: &str) -> Result<()>;
    pub async fn list_certificates(&self) -> Vec<CertificateInfo>;
    pub async fn validate_certificate(&self, domain: &str) -> Result<CertificateValidation>;
    pub async fn cleanup_expired_certificates(&mut self) -> Result<usize>;
    pub fn get_ca_certificate(&self) -> Option<&Certificate>;
}
```

### TLS Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_dir: String,
    pub auto_generate: bool,
    pub ca_name: String,
    pub key_type: KeyType,
    pub validity_days: u32,
    pub auto_renew: bool,
    pub renew_days_before: u32,
    pub additional_domains: Vec<String>,
    pub wildcard_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    RSA,
    ECDSA,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_dir: "~/.local/share/nebula/certs".to_string(),
            auto_generate: true,
            ca_name: "Nebula Development CA".to_string(),
            key_type: KeyType::ECDSA,
            validity_days: 365,
            auto_renew: true,
            renew_days_before: 30,
            additional_domains: vec![],
            wildcard_domains: vec![],
        }
    }
}
```

## Certificate Data Structures

### Certificate

Representation of a TLS certificate.

```rust
#[derive(Debug, Clone)]
pub struct Certificate {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub serial_number: String,
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub san_domains: Vec<String>,
    pub is_wildcard: bool,
    pub is_ca: bool,
}

impl Certificate {
    pub fn new(domain: String, cert_pem: String, key_pem: String) -> Self;
    pub fn from_rcgen_cert(cert: rcgen::Certificate) -> Result<Self>;
    pub fn to_rcgen_cert(&self) -> Result<rcgen::Certificate>;
    pub fn is_expired(&self) -> bool;
    pub fn is_expiring_soon(&self, days: u32) -> bool;
    pub fn get_remaining_days(&self) -> i64;
    pub fn validate(&self) -> Result<CertificateValidation>;
    pub fn save_to_files(&self, cert_path: &Path, key_path: &Path) -> Result<()>;
    pub fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<Self>;
}
```

### PrivateKey

Representation of a private key.

```rust
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub key_pem: String,
    pub key_type: KeyType,
    pub created_at: DateTime<Utc>,
    pub fingerprint: String,
}

impl PrivateKey {
    pub fn new(key_pem: String, key_type: KeyType) -> Self;
    pub fn from_rcgen_key(key: rcgen::KeyPair) -> Result<Self>;
    pub fn to_rcgen_key(&self) -> Result<rcgen::KeyPair>;
    pub fn generate(key_type: KeyType) -> Result<Self>;
    pub fn save_to_file(&self, path: &Path) -> Result<()>;
    pub fn load_from_file(path: &Path) -> Result<Self>;
}
```

### Certificate Information

Metadata about certificates for listing and management.

```rust
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub domain: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub serial_number: String,
    pub fingerprint: String,
    pub is_wildcard: bool,
    pub is_ca: bool,
    pub file_size: u64,
}

impl CertificateInfo {
    pub fn from_certificate(cert: &Certificate) -> Self;
    pub fn is_expired(&self) -> bool;
    pub fn is_expiring_soon(&self, days: u32) -> bool;
    pub fn get_remaining_days(&self) -> i64;
}
```

### Certificate Validation

Results of certificate validation.

```rust
#[derive(Debug, Clone)]
pub struct CertificateValidation {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub checks: ValidationChecks,
}

#[derive(Debug, Clone)]
pub enum ValidationError {
    Expired,
    NotYetValid,
    InvalidSignature,
    InvalidChain,
    InvalidDomain,
    InvalidKeyUsage,
    Revoked,
}

#[derive(Debug, Clone)]
pub enum ValidationWarning {
    ExpiringSoon(u32),
    WeakKeySize,
    ShortValidityPeriod,
    SelfSigned,
}

#[derive(Debug, Clone)]
pub struct ValidationChecks {
    pub signature_valid: bool,
    pub not_expired: bool,
    pub not_before_valid: bool,
    pub domain_matches: bool,
    pub chain_valid: bool,
    pub key_usage_valid: bool,
}
```

## Certificate Generation

### CA Certificate Management

```rust
impl CertificateManager {
    async fn generate_ca(&mut self) -> Result<()>;
    async fn load_ca(&mut self, cert_path: &Path, key_path: &Path) -> Result<()>;
    async fn save_ca(&self) -> Result<()>;
    fn get_ca_cert_path(&self) -> PathBuf;
    fn get_ca_key_path(&self) -> PathBuf;
    async fn regenerate_ca(&mut self) -> Result<()>;
}
```

### Domain Certificate Generation

```rust
impl CertificateManager {
    async fn generate_certificate(&mut self, domain: &str) -> Result<Certificate>;
    async fn generate_wildcard_certificate(&mut self, domain: &str) -> Result<Certificate>;
    async fn ensure_certificate(&mut self, domain: &str) -> Result<Certificate>;
    async fn get_or_create_certificate(&mut self, domain: &str) -> Result<Certificate>;
    
    fn create_certificate_request(&self, domain: &str, is_wildcard: bool) -> Result<rcgen::CertificateParams>;
    fn add_san_domains(&self, params: &mut rcgen::CertificateParams, domain: &str, is_wildcard: bool);
    fn create_key_pair(&self) -> Result<rcgen::KeyPair>;
}
```

### Certificate Request Parameters

```rust
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub domain: String,
    pub is_wildcard: bool,
    pub key_type: KeyType,
    pub validity_days: u32,
    pub san_domains: Vec<String>,
    pub key_usage: KeyUsage,
    pub extended_key_usage: ExtendedKeyUsage,
}

#[derive(Debug, Clone)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
}

#[derive(Debug, Clone)]
pub struct ExtendedKeyUsage {
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
}
```

## Certificate Validation

### Validation Engine

```rust
pub struct CertificateValidator {
    ca_cert: Option<Certificate>,
    trusted_cas: Vec<Certificate>,
    validation_config: ValidationConfig,
}

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub check_expiration: bool,
    pub check_signature: bool,
    pub check_chain: bool,
    pub check_revocation: bool,
    pub check_domain: bool,
    pub allow_self_signed: bool,
    pub expiration_warning_days: u32,
}

impl CertificateValidator {
    pub fn new() -> Self;
    pub fn with_ca(mut self, ca_cert: Certificate) -> Self;
    pub fn with_trusted_cas(mut self, cas: Vec<Certificate>) -> Self;
    pub fn with_config(mut self, config: ValidationConfig) -> Self;
    
    pub async fn validate(&self, cert: &Certificate, domain: Option<&str>) -> Result<CertificateValidation>;
    pub async fn validate_chain(&self, certs: &[Certificate]) -> Result<CertificateValidation>;
    pub async fn validate_file(&self, cert_path: &Path, domain: Option<&str>) -> Result<CertificateValidation>;
}
```

### Chain Validation

```rust
impl CertificateValidator {
    async fn validate_certificate_chain(&self, certs: &[Certificate]) -> Result<()>;
    async fn find_issuer(&self, cert: &Certificate, candidates: &[Certificate]) -> Option<Certificate>;
    async fn validate_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()>;
    async fn validate_key_usage(&self, cert: &Certificate, usage: KeyUsage) -> Result<()>;
    async fn validate_extended_key_usage(&self, cert: &Certificate, usage: ExtendedKeyUsage) -> Result<()>;
}
```

## Certificate Storage

### File System Storage

```rust
pub struct CertificateStorage {
    base_path: PathBuf,
    cert_format: CertificateFormat,
    key_format: KeyFormat,
}

#[derive(Debug, Clone)]
pub enum CertificateFormat {
    PEM,
    DER,
}

#[derive(Debug, Clone)]
pub enum KeyFormat {
    PEM,
    DER,
    PKCS8,
}

impl CertificateStorage {
    pub fn new(base_path: PathBuf) -> Self;
    pub fn with_formats(mut self, cert_format: CertificateFormat, key_format: KeyFormat) -> Self;
    
    pub async fn save_certificate(&self, cert: &Certificate) -> Result<()>;
    pub async fn load_certificate(&self, domain: &str) -> Result<Option<Certificate>>;
    pub async fn remove_certificate(&self, domain: &str) -> Result<()>;
    pub async fn list_certificates(&self) -> Result<Vec<CertificateInfo>>;
    pub async fn cleanup_expired(&self) -> Result<usize>;
    
    fn get_cert_path(&self, domain: &str) -> PathBuf;
    fn get_key_path(&self, domain: &str) -> PathBuf;
    fn get_ca_cert_path(&self) -> PathBuf;
    fn get_ca_key_path(&self) -> PathBuf;
}
```

### Certificate Backup

```rust
pub struct CertificateBackup {
    backup_dir: PathBuf,
    compression: bool,
    encryption: bool,
}

impl CertificateBackup {
    pub fn new(backup_dir: PathBuf) -> Self;
    pub fn with_compression(mut self, enabled: bool) -> Self;
    pub fn with_encryption(mut self, enabled: bool) -> Self;
    
    pub async fn backup_certificates(&self, cert_dir: &Path) -> Result<PathBuf>;
    pub async fn restore_certificates(&self, backup_path: &Path, target_dir: &Path) -> Result<()>;
    pub async fn list_backups(&self) -> Result<Vec<BackupInfo>>;
    pub async fn cleanup_old_backups(&self, keep_count: usize) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub size: u64,
    pub certificate_count: usize,
}
```

## Certificate Renewal

### Auto-Renewal System

```rust
pub struct CertificateRenewalManager {
    cert_manager: Arc<CertificateManager>,
    renewal_config: RenewalConfig,
    renewal_scheduler: RenewalScheduler,
}

#[derive(Debug, Clone)]
pub struct RenewalConfig {
    pub auto_renew: bool,
    pub renew_days_before: u32,
    pub check_interval: Duration,
    pub max_renewal_attempts: u32,
    pub renewal_backoff: Duration,
}

impl CertificateRenewalManager {
    pub fn new(cert_manager: Arc<CertificateManager>, config: RenewalConfig) -> Self;
    pub async fn start(&mut self) -> Result<()>;
    pub async fn stop(&mut self) -> Result<()>;
    pub async fn check_and_renew(&mut self) -> Result<RenewalResult>;
    pub async fn force_renewal(&mut self, domain: &str) -> Result<Certificate>;
    pub fn get_renewal_status(&self) -> RenewalStatus;
}

#[derive(Debug, Clone)]
pub struct RenewalResult {
    pub checked_count: usize,
    pub renewed_count: usize,
    pub failed_count: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RenewalStatus {
    pub is_running: bool,
    pub last_check: Option<DateTime<Utc>>,
    pub next_check: Option<DateTime<Utc>>,
    pub total_certificates: usize,
    pub expiring_soon: usize,
    pub auto_renewal_enabled: bool,
}
```

## Platform-Specific Certificate Installation

### macOS Certificate Installation

```rust
pub struct MacOSCertInstaller;

impl MacOSCertInstaller {
    pub async fn install_ca_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn remove_ca_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn is_ca_certificate_installed(&self, cert_path: &Path) -> bool;
    pub async fn trust_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn untrust_certificate(&self, cert_path: &Path) -> Result<()>;
}
```

### Linux Certificate Installation

```rust
pub struct LinuxCertInstaller;

impl LinuxCertInstaller {
    pub async fn install_ca_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn remove_ca_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn is_ca_certificate_installed(&self, cert_path: &Path) -> bool;
    pub async fn update_ca_certificates(&self) -> Result<()>;
}
```

### Windows Certificate Installation

```rust
pub struct WindowsCertInstaller;

impl WindowsCertInstaller {
    pub async fn install_ca_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn remove_ca_certificate(&self, cert_path: &Path) -> Result<()>;
    pub async fn is_ca_certificate_installed(&self, cert_path: &Path) -> bool;
    pub async fn install_to_store(&self, cert_path: &Path, store_name: &str) -> Result<()>;
}
```

## Certificate Statistics

### Certificate Metrics

```rust
#[derive(Debug, Clone, Default)]
pub struct CertificateStats {
    pub total_certificates: usize,
    pub ca_certificates: usize,
    pub domain_certificates: usize,
    pub wildcard_certificates: usize,
    pub expired_certificates: usize,
    pub expiring_soon: usize,
    pub auto_generated: usize,
    pub manually_created: usize,
    pub total_file_size: u64,
    pub last_renewal: Option<DateTime<Utc>>,
    pub renewal_success_rate: f64,
}

impl CertificateStats {
    pub fn from_certificates(certs: &[Certificate]) -> Self;
    pub fn get_utilization_percentage(&self) -> f64;
    pub fn get_expiration_distribution(&self) -> HashMap<String, usize>;
}
```

## API Usage Examples

### Basic Certificate Generation

```rust
use nebula::utils::certificates::{CertificateManager, TlsConfig};

async fn generate_certificate_example() -> Result<()> {
    let config = TlsConfig {
        cert_dir: "~/.local/share/nebula/certs".to_string(),
        auto_generate: true,
        ca_name: "My Custom CA".to_string(),
        key_type: KeyType::ECDSA,
        validity_days: 365,
        auto_renew: true,
        renew_days_before: 30,
        additional_domains: vec!["*.example.com".to_string()],
        wildcard_domains: vec![],
    };
    
    let mut cert_manager = CertificateManager::new_with_config(config).await?;
    
    // Ensure CA exists
    cert_manager.ensure_ca().await?;
    
    // Generate certificate for domain
    let cert = cert_manager.generate_certificate("app.example.com").await?;
    
    // Generate wildcard certificate
    let wildcard_cert = cert_manager.generate_wildcard_certificate("*.example.com").await?;
    
    println!("Generated certificate for: {}", cert.domain);
    println!("Expires at: {}", cert.expires_at);
    
    Ok(())
}
```

### Certificate Validation

```rust
use nebula::utils::certificates::{CertificateValidator, ValidationConfig};

async fn validate_certificate_example() -> Result<()> {
    let config = ValidationConfig {
        check_expiration: true,
        check_signature: true,
        check_chain: true,
        check_revocation: false,
        check_domain: true,
        allow_self_signed: true,
        expiration_warning_days: 30,
    };
    
    let validator = CertificateValidator::new()
        .with_config(config);
    
    let cert = Certificate::load_from_files(
        Path::new("cert.pem"),
        Path::new("key.pem")
    ).await?;
    
    let validation = validator.validate(&cert, Some("app.example.com")).await?;
    
    if validation.is_valid {
        println!("Certificate is valid");
    } else {
        println!("Certificate validation failed:");
        for error in &validation.errors {
            println!("  Error: {:?}", error);
        }
    }
    
    for warning in &validation.warnings {
        println!("  Warning: {:?}", warning);
    }
    
    Ok(())
}
```

### Auto-Renewal Setup

```rust
use nebula::utils::certificates::{CertificateRenewalManager, RenewalConfig};

async fn setup_auto_renewal_example() -> Result<()> {
    let cert_manager = Arc::new(CertificateManager::new().await?);
    
    let renewal_config = RenewalConfig {
        auto_renew: true,
        renew_days_before: 30,
        check_interval: Duration::from_secs(3600), // Check every hour
        max_renewal_attempts: 3,
        renewal_backoff: Duration::from_secs(60),
    };
    
    let mut renewal_manager = CertificateRenewalManager::new(cert_manager, renewal_config);
    
    // Start auto-renewal
    renewal_manager.start().await?;
    
    // Check renewal status
    let status = renewal_manager.get_renewal_status();
    println!("Auto-renewal running: {}", status.is_running);
    println!("Total certificates: {}", status.total_certificates);
    println!("Expiring soon: {}", status.expiring_soon);
    
    Ok(())
}
```

### Platform-Specific Installation

```rust
use nebula::utils::certificates::{MacOSCertInstaller, LinuxCertInstaller, WindowsCertInstaller};

async fn install_ca_certificate_example() -> Result<()> {
    let cert_path = Path::new("~/.local/share/nebula/certs/nebula-ca.crt");
    
    #[cfg(target_os = "macos")]
    {
        let installer = MacOSCertInstaller;
        installer.install_ca_certificate(cert_path).await?;
        installer.trust_certificate(cert_path).await?;
    }
    
    #[cfg(target_os = "linux")]
    {
        let installer = LinuxCertInstaller;
        installer.install_ca_certificate(cert_path).await?;
        installer.update_ca_certificates().await?;
    }
    
    #[cfg(target_os = "windows")]
    {
        let installer = WindowsCertInstaller;
        installer.install_ca_certificate(cert_path).await?;
        installer.install_to_store(cert_path, "Root").await?;
    }
    
    println!("CA certificate installed successfully");
    Ok(())
}
```

## Next Steps

- **Explore [Network API](network.md)** for DNS and DHCP functionality
- **Read [Core API](core.md)** for main server functionality
- **Check [Scheduler API](scheduler.md)** for production deployment
- **Review [Configuration API](configuration.md)** for config management
