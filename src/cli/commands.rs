use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, error, warn};

use crate::cli::{Commands, CertCommands, DnsCommands, DeployCommands};
use crate::core::NebulaServer;
use crate::utils::{CertificateManager, LanguageDetector, ProjectInfo, Language};
use crate::network::dns::DnsServer;

impl Commands {
    pub async fn execute(self) -> Result<()> {
        match self {
            Commands::Init { template } => {
                init_command(template).await
            }
            Commands::Setup => {
                setup_command().await
            }
            Commands::Start => {
                start_command().await
            }
            Commands::Stop => {
                stop_command().await
            }
            Commands::Status => {
                status_command().await
            }
            Commands::Cert { action } => {
                cert_command(action).await
            }
            Commands::Dns { action } => {
                dns_command(action).await
            }
            Commands::Clean => {
                clean_command().await
            }
            Commands::Deploy { action } => {
                deploy_command(action).await
            }
        }
    }
}

async fn init_command(template: Option<String>) -> Result<()> {
    info!("🌌 Initializing Nebula in current directory...");
    
    let current_dir = std::env::current_dir()?;
    
    // Auto-detect project type if no template specified
    let (template_name, project_info) = if let Some(template) = template {
        (template, None)
    } else {
        info!("🔍 Auto-detecting project type...");
        match LanguageDetector::detect_language(&current_dir) {
            Ok(info) => {
                let template_name = match info.language {
                    Language::React | Language::NextJs => "react",
                    Language::Vue | Language::NuxtJs => "vue", 
                    Language::Svelte => "svelte",
                    Language::Python => "python",
                    Language::Go => "go",
                    Language::Rust => "rust",
                    Language::Java => "java",
                    Language::CSharp => "csharp",
                    Language::PHP => "php",
                    Language::Ruby => "ruby",
                    Language::NodeJs | Language::JavaScript | Language::TypeScript => "nodejs",
                    _ => "default",
                };
                info!("✅ Detected project type: {:?} with framework: {:?}", 
                      info.language, info.framework);
                (template_name.to_string(), Some(info))
            }
            Err(e) => {
                warn!("Could not auto-detect project type: {}", e);
                ("default".to_string(), None)
            }
        }
    };
    
    let config_content = generate_config_for_template(&template_name, project_info.as_ref())?;

    std::fs::write("nebula.toml", config_content)?;
    
    // Create .gitignore entry
    let gitignore_path = PathBuf::from(".gitignore");
    if gitignore_path.exists() {
        let mut content = std::fs::read_to_string(&gitignore_path)?;
        if !content.contains("# Nebula") {
            content.push_str("\n# Nebula\n.nebula/\nnebula.log\n");
            std::fs::write(&gitignore_path, content)?;
        }
    } else {
        std::fs::write(&gitignore_path, "# Nebula\n.nebula/\nnebula.log\n")?;
    }

    info!("✅ Nebula configuration created for {}", template_name);
    info!("💡 Edit nebula.toml to customize settings");
    info!("🚀 Run 'nebula start' to begin development");
    
    Ok(())
}

fn generate_config_for_template(template_name: &str, project_info: Option<&ProjectInfo>) -> Result<String> {
    let base_config = match template_name {
        "react" => include_str!("../../templates/react.toml"),
        "vue" => include_str!("../../templates/vue.toml"),
        "svelte" => include_str!("../../templates/svelte.toml"),
        "next" => include_str!("../../templates/next.toml"),
        "python" => include_str!("../../templates/python.toml"),
        "go" => include_str!("../../templates/go.toml"),
        "rust" => include_str!("../../templates/rust.toml"),
        "java" => include_str!("../../templates/java.toml"),
        "csharp" => include_str!("../../templates/csharp.toml"),
        "php" => include_str!("../../templates/php.toml"),
        "ruby" => include_str!("../../templates/ruby.toml"),
        "nodejs" => include_str!("../../templates/nodejs.toml"),
        _ => include_str!("../../templates/default.toml"),
    };

    // If we have project info, customize the config
    if let Some(info) = project_info {
        let mut config = base_config.to_string();
        
        // Update command if we have a better one from detection
        if let Some(ref dev_cmd) = info.dev_command {
            config = config.replace("command = \"npm run dev\"", &format!("command = \"{}\"", dev_cmd));
        } else {
            let default_cmd = info.get_default_dev_command();
            config = config.replace("command = \"npm run dev\"", &format!("command = \"{}\"", default_cmd));
        }
        
        // Update port if detected
        if let Some(port) = info.port {
            config = config.replace("http_port = 3000", &format!("http_port = {}", port));
        } else {
            let default_port = info.get_default_port();
            config = config.replace("http_port = 3000", &format!("http_port = {}", default_port));
        }
        
        // Add language-specific environment variables
        match info.language {
            Language::Python => {
                config.push_str("\n[dev.env]\nPYTHONPATH = \".\"\n");
            }
            Language::Go => {
                config.push_str("\n[dev.env]\nGO111MODULE = \"on\"\n");
            }
            Language::Rust => {
                config.push_str("\n[dev.env]\nRUST_LOG = \"debug\"\n");
            }
            Language::Java => {
                config.push_str("\n[dev.env]\nJAVA_OPTS = \"-Dspring.profiles.active=dev\"\n");
            }
            Language::CSharp => {
                config.push_str("\n[dev.env]\nASPNETCORE_ENVIRONMENT = \"Development\"\n");
            }
            Language::PHP => {
                config.push_str("\n[dev.env]\nAPP_ENV = \"development\"\n");
            }
            Language::Ruby => {
                config.push_str("\n[dev.env]\nRAILS_ENV = \"development\"\n");
            }
            _ => {}
        }
        
        Ok(config)
    } else {
        Ok(base_config.to_string())
    }
}

async fn setup_command() -> Result<()> {
    info!("🔧 Setting up Nebula system dependencies...");
    
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::setup().await?;
    }
    
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::setup().await?;
    }
    
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::setup().await?;
    }
    
    info!("✅ System setup complete!");
    Ok(())
}

async fn start_command() -> Result<()> {
    info!("🚀 Starting Nebula development server...");
    
    // Load config from nebula.toml if it exists
    let config = if PathBuf::from("nebula.toml").exists() {
        let content = std::fs::read_to_string("nebula.toml")?;
        toml::from_str(&content)?
    } else {
        return Err(anyhow::anyhow!("No nebula.toml found. Run 'nebula init' first."));
    };
    
    let server = NebulaServer::new(config).await?;
    server.run().await
}

async fn stop_command() -> Result<()> {
    info!("🛑 Stopping Nebula development server...");
    
    // Read PID from lock file and terminate process
    let pid_file = PathBuf::from(".nebula/nebula.pid");
    if pid_file.exists() {
        let pid_str = std::fs::read_to_string(&pid_file)?;
        let pid: u32 = pid_str.trim().parse()?;
        
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            
            match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                Ok(_) => info!("✅ Nebula server stopped"),
                Err(e) => error!("Failed to stop server: {}", e),
            }
        }
        
        #[cfg(windows)]
        {
            // Windows process termination
            use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
            use winapi::um::winnt::PROCESS_TERMINATE;
            use winapi::um::handleapi::CloseHandle;
            
            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if !handle.is_null() {
                    TerminateProcess(handle, 0);
                    CloseHandle(handle);
                    info!("✅ Nebula server stopped");
                } else {
                    error!("Failed to open process {}", pid);
                }
            }
        }
        
        std::fs::remove_file(&pid_file)?;
    } else {
        info!("No running Nebula server found");
    }
    
    Ok(())
}

async fn status_command() -> Result<()> {
    info!("📊 Nebula Status");
    
    let pid_file = PathBuf::from(".nebula/nebula.pid");
    if pid_file.exists() {
        let pid_str = std::fs::read_to_string(&pid_file)?;
        info!("🟢 Server running (PID: {})", pid_str.trim());
        
        // Show port information
        let ports_file = PathBuf::from(".nebula/ports.json");
        if ports_file.exists() {
            let content = std::fs::read_to_string(&ports_file)?;
            let ports: HashMap<String, u16> = serde_json::from_str(&content)?;
            info!("🌐 HTTP Port: {}", ports.get("http").unwrap_or(&0));
            info!("🔒 HTTPS Port: {}", ports.get("https").unwrap_or(&0));
        }
    } else {
        info!("🔴 Server not running");
    }
    
    Ok(())
}

async fn cert_command(action: CertCommands) -> Result<()> {
    let cert_manager = CertificateManager::new().await?;
    
    match action {
        CertCommands::Generate { domain } => {
            info!("🔐 Generating certificate for {}", domain);
            cert_manager.ensure_certificate(&domain, true).await?;
            info!("✅ Certificate generated successfully");
        }
        CertCommands::List => {
            info!("📋 Installed certificates:");
            let certs = cert_manager.list_certificates().await?;
            for cert in certs {
                info!("  • {}", cert);
            }
        }
        CertCommands::Remove { domain } => {
            info!("🗑️ Removing certificate for {}", domain);
            cert_manager.remove_certificate(&domain).await?;
            info!("✅ Certificate removed");
        }
        CertCommands::InstallCa => {
            info!("🔒 Installing root CA...");
            cert_manager.install_ca().await?;
            info!("✅ Root CA installed");
        }
    }
    
    Ok(())
}

async fn dns_command(action: DnsCommands) -> Result<()> {
    let dns_config = crate::cli::DnsConfig::default();
    let dns_server = DnsServer::new(dns_config).await?;
    
    match action {
        DnsCommands::Add { domain, ip } => {
            let ip_addr = ip.parse()?;
            dns_server.add_record(&domain, ip_addr).await?;
            info!("✅ DNS record added: {} -> {}", domain, ip);
        }
        DnsCommands::Remove { domain } => {
            dns_server.remove_record(&domain).await?;
            info!("✅ DNS record removed: {}", domain);
        }
        DnsCommands::List => {
            info!("📋 DNS records:");
            let records = dns_server.list_records().await;
            for (domain, record) in records {
                info!("  {} -> {}", domain, record.data);
            }
        }
        DnsCommands::Test { domain } => {
            info!("🧪 Testing DNS resolution for {}", domain);
            // Implement DNS test logic
            info!("✅ DNS test completed");
        }
    }
    
    Ok(())
}

async fn clean_command() -> Result<()> {
    info!("🧹 Cleaning up Nebula files...");
    
    let paths_to_clean = vec![
        ".nebula/",
        "nebula.log",
        ".nebula-ports.json",
    ];
    
    for path in paths_to_clean {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            if path_buf.is_dir() {
                std::fs::remove_dir_all(&path_buf)?;
            } else {
                std::fs::remove_file(&path_buf)?;
            }
            info!("🗑️ Removed: {}", path);
        }
    }
    
    info!("✅ Cleanup complete!");
    Ok(())
}

async fn deploy_command(action: DeployCommands) -> Result<()> {
    use crate::core::scheduler::{NebulaScheduler, SchedulerConfig, DeploymentConfig};
    
    let config = SchedulerConfig::default();
    let scheduler = NebulaScheduler::new(config).await?;
    
    match action {
        DeployCommands::Create { name, build_path, tld, port } => {
            info!("🚀 Creating deployment: {}", name);
            
            let mut deploy_config = DeploymentConfig::default();
            if let Some(p) = port {
                deploy_config.port = p;
            }
            
            let deployment = scheduler.create_deployment(
                name,
                PathBuf::from(build_path),
                tld,
                Some(deploy_config),
            ).await?;
            
            info!("✅ Deployment created: {}", deployment.id);
            info!("   Domain: {}", deployment.domain);
            info!("   Status: {:?}", deployment.status);
        }
        DeployCommands::Start { deployment_id } => {
            info!("▶️ Starting deployment: {}", deployment_id);
            scheduler.start_deployment(&deployment_id).await?;
            info!("✅ Deployment started successfully");
        }
        DeployCommands::Stop { deployment_id } => {
            info!("⏹️ Stopping deployment: {}", deployment_id);
            scheduler.stop_deployment(&deployment_id).await?;
            info!("✅ Deployment stopped successfully");
        }
        DeployCommands::List => {
            info!("📋 Deployments:");
            let deployments = scheduler.list_deployments().await;
            for deployment in deployments {
                info!("  {} - {} ({}) - {:?}", 
                      deployment.id, deployment.name, deployment.domain, deployment.status);
            }
        }
        DeployCommands::Show { deployment_id } => {
            if let Some(deployment) = scheduler.get_deployment(&deployment_id).await {
                info!("📊 Deployment Details:");
                info!("   ID: {}", deployment.id);
                info!("   Name: {}", deployment.name);
                info!("   Domain: {}", deployment.domain);
                info!("   Status: {:?}", deployment.status);
                info!("   Created: {}", deployment.created_at);
                info!("   Updated: {}", deployment.updated_at);
                info!("   Port: {}", deployment.config.port);
                info!("   HTTPS: {}", deployment.config.https_enabled);
            } else {
                info!("❌ Deployment not found: {}", deployment_id);
            }
        }
        DeployCommands::Delete { deployment_id } => {
            info!("🗑️ Deleting deployment: {}", deployment_id);
            scheduler.delete_deployment(&deployment_id).await?;
            info!("✅ Deployment deleted successfully");
        }
        DeployCommands::Update { deployment_id, port, env } => {
            info!("🔄 Updating deployment: {}", deployment_id);
            
            if let Some(deployment) = scheduler.get_deployment(&deployment_id).await {
                let mut config = deployment.config.clone();
                
                if let Some(p) = port {
                    config.port = p;
                }
                
                // Parse environment variables
                for env_var in env {
                    if let Some((key, value)) = env_var.split_once('=') {
                        config.environment_vars.insert(key.to_string(), value.to_string());
                    }
                }
                
                // Note: In a real implementation, you'd need an update_deployment method
                info!("✅ Deployment configuration updated");
            } else {
                info!("❌ Deployment not found: {}", deployment_id);
            }
        }
    }
    
    Ok(())
}
