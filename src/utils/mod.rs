pub mod certificates;
pub mod language_detector;
pub mod logging;
pub mod ports;

pub use certificates::CertificateManager;
pub use language_detector::{LanguageDetector, ProjectInfo, Language};
pub use logging::init as init_logging;
pub use ports::PortManager;

use crate::error::{NebulaError, Result as NebulaResult};
use std::path::Path;
use tracing::debug;

/// Utility functions for common operations
pub struct NebulaUtils;

impl NebulaUtils {
    /// Check if a directory is a valid project directory
    pub fn is_valid_project_dir(path: &Path) -> bool {
        if !path.exists() || !path.is_dir() {
            return false;
        }

        // Check for common project indicators
        let indicators = [
            "package.json",
            "Cargo.toml", 
            "go.mod",
            "pom.xml",
            "requirements.txt",
            "Gemfile",
            "composer.json",
            "*.csproj",
            "*.sln"
        ];

        for indicator in &indicators {
            if indicator.contains('*') {
                // Handle wildcard patterns
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let file_name = entry.file_name();
                        let file_str = file_name.to_string_lossy();
                        if indicator.ends_with(".csproj") && file_str.ends_with(".csproj") {
                            return true;
                        }
                        if indicator.ends_with(".sln") && file_str.ends_with(".sln") {
                            return true;
                        }
                    }
                }
            } else if path.join(indicator).exists() {
                return true;
            }
        }

        false
    }

    /// Sanitize a domain name for use as a filename
    pub fn sanitize_domain_for_filename(domain: &str) -> String {
        domain
            .chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
                '.' => '_',
                _ => '-',
            })
            .collect()
    }

    /// Get a human-readable file size
    pub fn format_file_size(size: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        
        if size == 0 {
            return "0 B".to_string();
        }

        let mut size = size as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{:.0} {}", size, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }

    /// Check if a string is a valid semantic version
    pub fn is_valid_semver(version: &str) -> bool {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        parts.iter().all(|part| {
            part.chars().all(|c| c.is_ascii_digit()) && !part.is_empty()
        })
    }

    /// Generate a random string of specified length
    pub fn generate_random_string(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Validate an email address (basic validation)
    pub fn is_valid_email(email: &str) -> bool {
        email.contains('@') && 
        email.chars().all(|c| c.is_ascii()) &&
        !email.starts_with('@') &&
        !email.ends_with('@') &&
        email.split('@').count() == 2
    }

    /// Get the current timestamp in RFC3339 format
    pub fn current_timestamp() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    /// Calculate SHA-256 hash of a string
    pub fn sha256_hash(input: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        format!("{:x}", result)
    }

    /// Retry an async operation with exponential backoff
    pub async fn retry_with_backoff<F, Fut, T, E>(
        mut operation: F,
        max_attempts: u32,
        initial_delay: std::time::Duration,
    ) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut delay = initial_delay;
        
        for attempt in 1..=max_attempts {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt == max_attempts {
                        return Err(e);
                    }
                    
                    debug!("Attempt {} failed: {}, retrying in {:?}", attempt, e, delay);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, std::time::Duration::from_secs(60));
                }
            }
        }
        
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_domain_for_filename() {
        assert_eq!(NebulaUtils::sanitize_domain_for_filename("example.com"), "example_com");
        assert_eq!(NebulaUtils::sanitize_domain_for_filename("sub.example.com"), "sub_example_com");
        assert_eq!(NebulaUtils::sanitize_domain_for_filename("test@domain.com"), "test-domain_com");
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(NebulaUtils::format_file_size(0), "0 B");
        assert_eq!(NebulaUtils::format_file_size(512), "512 B");
        assert_eq!(NebulaUtils::format_file_size(1024), "1.0 KB");
        assert_eq!(NebulaUtils::format_file_size(1536), "1.5 KB");
        assert_eq!(NebulaUtils::format_file_size(1048576), "1.0 MB");
    }

    #[test]
    fn test_is_valid_semver() {
        assert!(NebulaUtils::is_valid_semver("1.0.0"));
        assert!(NebulaUtils::is_valid_semver("0.1.0"));
        assert!(NebulaUtils::is_valid_semver("10.20.30"));
        assert!(!NebulaUtils::is_valid_semver("1.0"));
        assert!(!NebulaUtils::is_valid_semver("1.0.0-alpha"));
        assert!(!NebulaUtils::is_valid_semver("v1.0.0"));
    }

    #[test]
    fn test_generate_random_string() {
        let str1 = NebulaUtils::generate_random_string(10);
        let str2 = NebulaUtils::generate_random_string(10);
        
        assert_eq!(str1.len(), 10);
        assert_eq!(str2.len(), 10);
        assert_ne!(str1, str2); // Very unlikely to be the same
    }

    #[test]
    fn test_is_valid_email() {
        assert!(NebulaUtils::is_valid_email("test@example.com"));
        assert!(NebulaUtils::is_valid_email("user.name@domain.org"));
        assert!(!NebulaUtils::is_valid_email("invalid.email"));
        assert!(!NebulaUtils::is_valid_email("@example.com"));
        assert!(!NebulaUtils::is_valid_email("test@"));
    }

    #[test]
    fn test_sha256_hash() {
        let hash1 = NebulaUtils::sha256_hash("hello");
        let hash2 = NebulaUtils::sha256_hash("hello");
        let hash3 = NebulaUtils::sha256_hash("world");
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex characters
    }

    #[test]
    fn test_is_valid_project_dir() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path();
        
        // Empty directory should not be valid
        assert!(!NebulaUtils::is_valid_project_dir(project_dir));
        
        // Create package.json
        std::fs::write(project_dir.join("package.json"), "{}").unwrap();
        assert!(NebulaUtils::is_valid_project_dir(project_dir));
    }

    #[tokio::test]
    async fn test_retry_with_backoff() {
        let mut attempts = 0;
        
        let result = NebulaUtils::retry_with_backoff(
            || {
                attempts += 1;
                async move {
                    if attempts < 3 {
                        Err("Temporary failure")
                    } else {
                        Ok("Success")
                    }
                }
            },
            5,
            std::time::Duration::from_millis(10),
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Success");
        assert_eq!(attempts, 3);
    }
}
