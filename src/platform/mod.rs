#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

use crate::error::{NebulaError, Result as NebulaResult};

/// Platform-specific utilities
pub struct PlatformUtils;

impl PlatformUtils {
    /// Get the current platform name
    pub fn get_platform_name() -> &'static str {
        #[cfg(target_os = "macos")]
        return "macOS";
        
        #[cfg(target_os = "linux")]
        return "Linux";
        
        #[cfg(target_os = "windows")]
        return "Windows";
        
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return "Unknown";
    }

    /// Check if running with elevated privileges
    pub fn is_elevated() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
            use winapi::um::securitybaseapi::GetTokenInformation;
            use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
            use winapi::um::handleapi::CloseHandle;

            unsafe {
                let mut token = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return false;
                }

                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut size = 0;
                let result = GetTokenInformation(
                    token,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut size,
                );

                CloseHandle(token);

                if result == 0 {
                    return false;
                }

                elevation.TokenIsElevated != 0
            }
        }
    }

    /// Get system information
    pub fn get_system_info() -> SystemInfo {
        SystemInfo {
            platform: Self::get_platform_name().to_string(),
            is_elevated: Self::is_elevated(),
            architecture: std::env::consts::ARCH.to_string(),
            family: std::env::consts::FAMILY.to_string(),
        }
    }

    /// Check if a command exists in PATH
    pub fn command_exists(command: &str) -> bool {
        which::which(command).is_ok()
    }

    /// Get the default shell for the platform
    pub fn get_default_shell() -> &'static str {
        #[cfg(unix)]
        return "/bin/bash";
        
        #[cfg(windows)]
        return "cmd.exe";
    }

    /// Get platform-specific configuration directory
    pub fn get_config_dir() -> std::path::PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("nebula")
    }

    /// Get platform-specific data directory
    pub fn get_data_dir() -> std::path::PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("nebula")
    }

    /// Get platform-specific cache directory
    pub fn get_cache_dir() -> std::path::PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("nebula")
    }
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub platform: String,
    pub is_elevated: bool,
    pub architecture: String,
    pub family: String,
}

/// Platform-specific setup functions
pub async fn setup_platform(no_packages: bool, no_dns_setup: bool, no_firewall: bool) -> NebulaResult<()> {
    #[cfg(target_os = "macos")]
    {
        macos::setup(no_packages, no_dns_setup, no_firewall).await
    }
    
    #[cfg(target_os = "linux")]
    {
        linux::setup(no_packages, no_dns_setup, no_firewall).await
    }
    
    #[cfg(target_os = "windows")]
    {
        windows::setup(no_packages, no_dns_setup, no_firewall).await
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        tracing::warn!("Platform-specific setup not available for this OS");
        Ok(())
    }
}

/// Platform-specific cleanup functions
pub async fn cleanup_platform() -> NebulaResult<()> {
    #[cfg(target_os = "macos")]
    {
        macos::cleanup().await
    }
    
    #[cfg(target_os = "linux")]
    {
        linux::cleanup().await
    }
    
    #[cfg(target_os = "windows")]
    {
        windows::cleanup().await
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(())
    }
}
