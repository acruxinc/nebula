use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, error, warn, debug};
use tokio::fs;
use std::process::Stdio;
use tokio::process::Command;
use regex::Regex;

use crate::cli::{Commands, CertCommands, DnsCommands, DeployCommands, ConfigCommands};
use crate::core::NebulaServer;
use crate::utils::{CertificateManager, LanguageDetector, ProjectInfo, Language};
use crate::network::dns::DnsServer;
use crate::error::{NebulaError, Result as NebulaResult};
use crate::cli::config::NebulaConfig;

impl Commands {
    pub async fn execute(self) -> NebulaResult<()> {
        match self {
            Commands::Init { template, no_detect, force } => {
                init_command(template, no_detect, force).await
            }
            Commands::Setup { no_packages, no_dns_setup, no_firewall } => {
                setup_command(no_packages, no_dns_setup, no_firewall).await
            }
            Commands::Start { daemon, pid_file } => {
                start_command(daemon, pid_file).await
            }
            Commands::Stop { pid_file, force } => {
                stop_command(pid_file, force).await
            }
            Commands::Status { format } => {
                status_command(&format).await
            }
            Commands::Cert { action } => {
                cert_command(action).await
            }
            Commands::Dns { action } => {
                dns_command(action).await
            }
            Commands::Clean { certs, logs, all } => {
                clean_command(certs, logs, all).await
            }
            Commands::Deploy { action } => {
                deploy_command(action).await
            }
            Commands::Config { action } => {
                config_command(action).await
            }
            Commands::Health { component, timeout } => {
                health_command(component.as_deref(), timeout).await
            }
        }
    }
}

async fn init_command(template: Option<String>, no_detect: bool, force: bool) -> NebulaResult<()> {
    info!("🌌 Initializing Nebula in current directory...");
    
    let current_dir = std::env::current_dir()
        .map_err(|e| NebulaError::config(format!("Failed to get current directory: {}", e)))?;
    
    let config_path = current_dir.join("nebula.toml");
    
    // Check if config already exists
    if config_path.exists() && !force {
        return Err(NebulaError::already_exists("Configuration file nebula.toml already exists. Use --force to overwrite"));
    }
    
    // Auto-detect project type if no template specified and detection is enabled
    let (template_name, project_info) = if let Some(template) = template {
        (template, None)
    } else if !no_detect {
        info!("🔍 Auto-detecting project type...");
        match LanguageDetector::detect_language(&current_dir).await {
            Ok(info) => {
                let template_name = get_template_name_for_language(&info.language, &info.framework);
                info!("✅ Detected project type: {:?} with framework: {:?}", 
                      info.language, info.framework);
                (template_name, Some(info))
            }
            Err(e) => {
                warn!("Could not auto-detect project type: {}", e);
                ("default".to_string(), None)
            }
        }
    } else {
        ("default".to_string(), None)
    };
    
    // Generate configuration
    let config = generate_config_for_template(&template_name, project_info.as_ref())?;
    
    // Write configuration file
    config.save_to_file(&config_path).await?;
    
    // Create .gitignore entry
    update_gitignore(&current_dir).await?;
    
    // Create necessary directories
    create_nebula_directories(&current_dir).await?;
    
    info!("✅ Nebula configuration created for {}", template_name);
    info!("💡 Edit nebula.toml to customize settings");
    info!("🚀 Run 'nebula start' to begin development");
    
    // Show next steps based on detected project
    if let Some(info) = project_info {
        show_project_specific_tips(&info).await?;
    }
    
    Ok(())
}

async fn setup_command(no_packages: bool, no_dns_setup: bool, no_firewall: bool) -> NebulaResult<()> {
    info!("🔧 Setting up Nebula system dependencies...");
    
    // Platform-specific setup
    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::setup(no_packages, no_dns_setup, no_firewall).await?;
    }
    
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::setup(no_packages, no_dns_setup, no_firewall).await?;
    }
    
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::setup(no_packages, no_dns_setup, no_firewall).await?;
    }
    
    // Setup certificates
    let mut cert_manager = CertificateManager::new().await?;
    cert_manager.ensure_ca().await?;
    
    info!("✅ System setup complete!");
    info!("💡 You can now run 'nebula init' in your project directory");
    
    Ok(())
}

async fn start_command(daemon: bool, pid_file: Option<PathBuf>) -> NebulaResult<()> {
    info!("🚀 Starting Nebula development server...");
    
    // Load configuration
    let config_path = PathBuf::from("nebula.toml");
    if !config_path.exists() {
        return Err(NebulaError::file_not_found("nebula.toml not found. Run 'nebula init' first"));
    }
    
    let config = NebulaConfig::load_from_file(&config_path).await?;
    
    if daemon {
        start_daemon(config, pid_file).await
    } else {
        start_foreground(config).await
    }
}

async fn start_foreground(config: NebulaConfig) -> NebulaResult<()> {
    let server = NebulaServer::new(config).await?;
    
    // Setup graceful shutdown
    let server_clone = server.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("Received shutdown signal...");
        if let Err(e) = server_clone.shutdown().await {
            error!("Error during shutdown: {}", e);
        }
    });
    
    server.run().await
}

async fn start_daemon(config: NebulaConfig, pid_file: Option<PathBuf>) -> NebulaResult<()> {
    let pid_file = pid_file.unwrap_or_else(|| PathBuf::from(".nebula/nebula.pid"));
    
    // Check if already running
    if let Ok(existing_pid) = read_pid_file(&pid_file).await {
        if is_process_running(existing_pid) {
            return Err(NebulaError::already_exists(format!("Nebula is already running with PID {}", existing_pid)));
        }
    }
    
    // Create daemon process
    let current_exe = std::env::current_exe()
        .map_err(|e| NebulaError::platform(format!("Failed to get current executable: {}", e)))?;
    
    let mut cmd = Command::new(current_exe);
    cmd.args(&["start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    
    let child = cmd.spawn()
        .map_err(|e| NebulaError::command_failed(format!("Failed to spawn daemon: {}", e)))?;
    
    let pid = child.id().ok_or_else(|| NebulaError::platform("Failed to get daemon PID"))?;
    
    // Write PID file
    write_pid_file(&pid_file, pid).await?;
    
    info!("✅ Nebula daemon started with PID {}", pid);
    Ok(())
}

async fn stop_command(pid_file: Option<PathBuf>, force: bool) -> NebulaResult<()> {
    info!("🛑 Stopping Nebula development server...");
    
    let pid_file = pid_file.unwrap_or_else(|| PathBuf::from(".nebula/nebula.pid"));
    
    let pid = read_pid_file(&pid_file).await
        .map_err(|_| NebulaError::not_found("No running Nebula server found"))?;
    
    if !is_process_running(pid) {
        warn!("Process {} is not running", pid);
        let _ = fs::remove_file(&pid_file).await;
        return Ok(());
    }
    
    // Try graceful shutdown first
    if !force {
        if terminate_process(pid, false).await? {
            info!("✅ Nebula server stopped gracefully");
        } else {
            warn!("Graceful shutdown failed, forcing termination...");
            terminate_process(pid, true).await?;
            info!("✅ Nebula server force stopped");
        }
    } else {
        terminate_process(pid, true).await?;
        info!("✅ Nebula server force stopped");
    }
    
    // Clean up PID file
    let _ = fs::remove_file(&pid_file).await;
    
    Ok(())
}

async fn status_command(format: &str) -> NebulaResult<()> {
    let status = get_server_status().await?;
    
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&status)?;
            println!("{}", json);
        }
        "text" | _ => {
            print_status_text(&status).await?;
        }
    }
    
    Ok(())
}

async fn cert_command(action: CertCommands) -> NebulaResult<()> {
    let cert_manager = CertificateManager::new().await?;
    
    match action {
        CertCommands::Generate { domain, wildcard, validity_days } => {
            info!("🔐 Generating certificate for {}", domain);
            
            if wildcard {
                let wildcard_domain = if domain.starts_with("*.") {
                    domain
                } else {
                    format!("*.{}", domain)
                };
                cert_manager.generate_wildcard_certificate(&wildcard_domain, validity_days).await?;
            } else {
                cert_manager.generate_certificate(&domain, validity_days).await?;
            }
            
            info!("✅ Certificate generated successfully");
        }
        CertCommands::List { show_expired, format } => {
            let certs = cert_manager.list_certificates(show_expired).await?;
            print_certificates(&certs, &format).await?;
        }
        CertCommands::Remove { domain, all } => {
            if all {
                cert_manager.remove_all_certificates(&domain).await?;
                info!("✅ All certificates for {} removed", domain);
            } else {
                cert_manager.remove_certificate(&domain).await?;
                info!("✅ Certificate for {} removed", domain);
            }
        }
        CertCommands::InstallCa { store } => {
            info!("🔒 Installing root CA...");
            cert_manager.install_ca(store.as_deref()).await?;
            info!("✅ Root CA installed");
        }
        CertCommands::RemoveCa => {
            info!("🗑️ Removing root CA...");
            cert_manager.remove_ca().await?;
            info!("✅ Root CA removed");
        }
        CertCommands::Verify { domain } => {
            let is_valid = cert_manager.verify_certificate(&domain).await?;
            if is_valid {
                info!("✅ Certificate for {} is valid", domain);
            } else {
                warn!("❌ Certificate for {} is invalid or expired", domain);
            }
        }
        CertCommands::Renew { all, days_before } => {
            if all {
                let renewed = cert_manager.renew_all_certificates(days_before).await?;
                info!("✅ Renewed {} certificates", renewed);
            } else {
                return Err(NebulaError::validation("Must specify --all for renew command"));
            }
        }
    }
    
    Ok(())
}

async fn dns_command(action: DnsCommands) -> NebulaResult<()> {
    let config = load_current_config().await?;
    let dns_server = DnsServer::new(config.dns).await?;
    
    match action {
        DnsCommands::Add { domain, ip, record_type, ttl } => {
            let ip_addr = ip.parse()
                .map_err(|_| NebulaError::invalid_domain(format!("Invalid IP address: {}", ip)))?;
            
            dns_server.add_record(&domain, &record_type, &ip_addr.to_string(), ttl).await?;
            info!("✅ DNS record added: {} {} -> {}", domain, record_type, ip);
        }
        DnsCommands::Remove { domain, all } => {
            if all {
                dns_server.remove_all_records(&domain).await?;
                info!("✅ All DNS records for {} removed", domain);
            } else {
                dns_server.remove_record(&domain).await?;
                info!("✅ DNS record removed: {}", domain);
            }
        }
        DnsCommands::List { filter, format } => {
            let records = dns_server.list_records(filter.as_deref()).await?;
            print_dns_records(&records, &format).await?;
        }
        DnsCommands::Test { domain, server, record_type } => {
            let result = dns_server.test_resolution(&domain, server.as_deref(), &record_type).await?;
            print_dns_test_result(&domain, &result).await?;
        }
        DnsCommands::Flush => {
            dns_server.flush_cache().await?;
            info!("✅ DNS cache flushed");
        }
        DnsCommands::Stats => {
            let stats = dns_server.get_statistics().await?;
            print_dns_statistics(&stats).await?;
        }
    }
    
    Ok(())
}

async fn deploy_command(action: DeployCommands) -> NebulaResult<()> {
    use crate::core::scheduler::{NebulaScheduler, DeploymentConfig};
    
    let config = load_current_config().await?;
    let scheduler = NebulaScheduler::new(config.scheduler).await?;
    
    match action {
        DeployCommands::Create { name, build_path, tld, port, env, health_check, start } => {
            info!("🚀 Creating deployment: {}", name);
            
            if !build_path.exists() {
                return Err(NebulaError::file_not_found(format!("Build path does not exist: {:?}", build_path)));
            }
            
            let mut deploy_config = DeploymentConfig::default();
            if let Some(p) = port {
                deploy_config.port = p;
            }
            
            // Parse environment variables
            for env_var in env {
                if let Some((key, value)) = env_var.split_once('=') {
                    deploy_config.environment_vars.insert(key.to_string(), value.to_string());
                } else {
                    return Err(NebulaError::validation(format!("Invalid environment variable format: {}", env_var)));
                }
            }
            
            if let Some(health_path) = health_check {
                deploy_config.health_check_path = Some(health_path);
            }
            
            let deployment = scheduler.create_deployment(
                name,
                build_path,
                tld,
                Some(deploy_config),
            ).await?;
            
            info!("✅ Deployment created: {}", deployment.id);
            info!("   Domain: {}", deployment.domain);
            info!("   Status: {:?}", deployment.status);
            
            if start {
                scheduler.start_deployment(&deployment.id).await?;
                info!("✅ Deployment started");
            }
        }
        DeployCommands::Start { deployment_id, wait, timeout } => {
            info!("▶️ Starting deployment: {}", deployment_id);
            scheduler.start_deployment(&deployment_id).await?;
            
            if wait {
                wait_for_deployment_ready(&scheduler, &deployment_id, timeout).await?;
            }
            
            info!("✅ Deployment started successfully");
        }
        DeployCommands::Stop { deployment_id, force } => {
            info!("⏹️ Stopping deployment: {}", deployment_id);
            scheduler.stop_deployment(&deployment_id, force).await?;
            info!("✅ Deployment stopped successfully");
        }
        DeployCommands::List { status, format } => {
            let deployments = scheduler.list_deployments(status.as_deref()).await?;
            print_deployments(&deployments, &format).await?;
        }
        DeployCommands::Show { deployment_id, follow } => {
            let deployment = scheduler.get_deployment(&deployment_id).await
                .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;
            
            print_deployment_details(&deployment).await?;
            
            if follow {
                follow_deployment_logs(&scheduler, &deployment_id).await?;
            }
        }
        DeployCommands::Delete { deployment_id, force } => {
            if !force {
                print!("Are you sure you want to delete deployment {}? [y/N]: ", deployment_id);
                use std::io::{self, Write};
                io::stdout().flush().unwrap();
                
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                
                if !input.trim().to_lowercase().starts_with('y') {
                    info!("Operation cancelled");
                    return Ok(());
                }
            }
            
            info!("🗑️ Deleting deployment: {}", deployment_id);
            scheduler.delete_deployment(&deployment_id).await?;
            info!("✅ Deployment deleted successfully");
        }
        DeployCommands::Update { deployment_id, port, env, remove_env } => {
            info!("🔄 Updating deployment: {}", deployment_id);
            
            let mut updates = HashMap::new();
            
            if let Some(p) = port {
                updates.insert("port".to_string(), p.to_string());
            }
            
            for env_var in env {
                if let Some((key, value)) = env_var.split_once('=') {
                    updates.insert(format!("env.{}", key), value.to_string());
                }
            }
            
            for key in remove_env {
                updates.insert(format!("remove_env.{}", key), String::new());
            }
            
            scheduler.update_deployment(&deployment_id, updates).await?;
            info!("✅ Deployment updated successfully");
        }
        DeployCommands::Restart { deployment_id } => {
            info!("🔄 Restarting deployment: {}", deployment_id);
            scheduler.restart_deployment(&deployment_id).await?;
            info!("✅ Deployment restarted successfully");
        }
        DeployCommands::Scale { deployment_id, replicas } => {
            info!("📈 Scaling deployment {} to {} replicas", deployment_id, replicas);
            scheduler.scale_deployment(&deployment_id, replicas).await?;
            info!("✅ Deployment scaled successfully");
        }
        DeployCommands::Logs { deployment_id, follow, lines } => {
            if follow {
                follow_deployment_logs(&scheduler, &deployment_id).await?;
            } else {
                let logs = scheduler.get_deployment_logs(&deployment_id, lines).await?;
                for log_line in logs {
                    println!("{}", log_line);
                }
            }
        }
    }
    
    Ok(())
}

async fn config_command(action: ConfigCommands) -> NebulaResult<()> {
    match action {
        ConfigCommands::Show { section, format } => {
            let config = load_current_config().await?;
            print_config(&config, section.as_deref(), &format).await?;
        }
        ConfigCommands::Validate { file } => {
            let config_path = file.unwrap_or_else(|| PathBuf::from("nebula.toml"));
            let config = NebulaConfig::load_from_file(&config_path).await?;
            config.validate()?;
            info!("✅ Configuration is valid");
        }
        ConfigCommands::Set { key, value } => {
            let mut config = load_current_config().await?;
            set_config_value(&mut config, &key, &value)?;
            config.save_to_file(&PathBuf::from("nebula.toml")).await?;
            info!("✅ Configuration updated: {} = {}", key, value);
        }
        ConfigCommands::Get { key } => {
            let config = load_current_config().await?;
            let value = get_config_value(&config, &key)?;
            println!("{}", value);
        }
        ConfigCommands::Reset { confirm } => {
            if !confirm {
                return Err(NebulaError::validation("Use --confirm to reset configuration"));
            }
            
            let default_config = NebulaConfig::default();
            default_config.save_to_file(&PathBuf::from("nebula.toml")).await?;
            info!("✅ Configuration reset to defaults");
        }
    }
    
    Ok(())
}

async fn health_command(component: Option<&str>, timeout: u64) -> NebulaResult<()> {
    let timeout_duration = std::time::Duration::from_secs(timeout);
    
    match component {
        Some("dns") => check_dns_health(timeout_duration).await?,
        Some("certs") => check_cert_health(timeout_duration).await?,
        Some("server") => check_server_health(timeout_duration).await?,
        None => {
            info!("🏥 Running full health check...");
            check_dns_health(timeout_duration).await?;
            check_cert_health(timeout_duration).await?;
            check_server_health(timeout_duration).await?;
            info!("✅ All components healthy");
        }
        Some(unknown) => {
            return Err(NebulaError::validation(format!("Unknown component: {}", unknown)));
        }
    }
    
    Ok(())
}

async fn clean_command(certs: bool, logs: bool, all: bool) -> NebulaResult<()> {
    info!("🧹 Cleaning up Nebula files...");
    
    let mut cleaned_count = 0;
    
    // Always clean runtime files
    let runtime_files = vec![
        ".nebula/nebula.pid",
        ".nebula/ports.json",
        ".nebula/server.json",
    ];
    
    for file in runtime_files {
        let path = PathBuf::from(file);
        if path.exists() {
            fs::remove_file(&path).await?;
            cleaned_count += 1;
            debug!("Removed: {}", file);
        }
    }
    
    // Clean certificates if requested
    if certs || all {
        let cert_manager = CertificateManager::new().await?;
        let removed = cert_manager.clean_all_certificates().await?;
        cleaned_count += removed;
        info!("🗑️ Removed {} certificates", removed);
    }
    
    // Clean logs if requested
    if logs || all {
        let log_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nebula")
            .join("logs");
        
        if log_dir.exists() {
            let removed = clean_directory(&log_dir).await?;
            cleaned_count += removed;
            info!("🗑️ Removed {} log files", removed);
        }
    }
    
    // Clean everything if requested
    if all {
        let nebula_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nebula");
        
        if nebula_dir.exists() {
            let removed = clean_directory(&nebula_dir).await?;
            cleaned_count += removed;
            info!("🗑️ Removed {} files from nebula directory", removed);
        }
    }
    
    info!("✅ Cleanup complete! Removed {} files", cleaned_count);
    Ok(())
}

// Helper functions

fn get_template_name_for_language(language: &Language, framework: &Option<String>) -> String {
    match language {
        Language::React => "react".to_string(),
        Language::Vue => "vue".to_string(),
        Language::Angular => "angular".to_string(),
        Language::Svelte => "svelte".to_string(),
        Language::NextJs => "next".to_string(),
        Language::NuxtJs => "nuxt".to_string(),
        Language::Python => {
            match framework.as_ref().map(|s| s.as_str()) {
                Some("django") => "django".to_string(),
                Some("flask") => "flask".to_string(),
                Some("fastapi") => "fastapi".to_string(),
                _ => "python".to_string(),
            }
        }
        Language::Go => "go".to_string(),
        Language::Rust => "rust".to_string(),
        Language::Java => "java".to_string(),
        Language::CSharp => "csharp".to_string(),
        Language::PHP => "php".to_string(),
        Language::Ruby => "ruby".to_string(),
        Language::NodeJs | Language::JavaScript | Language::TypeScript => "nodejs".to_string(),
        _ => "default".to_string(),
    }
}

fn generate_config_for_template(template_name: &str, project_info: Option<&ProjectInfo>) -> NebulaResult<NebulaConfig> {
    let mut config = NebulaConfig::default();
    
    // Load template-specific defaults
    match template_name {
        "react" | "vue" | "angular" | "svelte" => {
            config.dev_command = "npm run dev".to_string();
            config.http_port = 3000;
        }
        "next" => {
            config.dev_command = "npm run dev".to_string();
            config.http_port = 3000;
        }
        "python" => {
            config.dev_command = "python main.py".to_string();
            config.http_port = 8000;
        }
        "django" => {
            config.dev_command = "python manage.py runserver".to_string();
            config.http_port = 8000;
        }
        "flask" => {
            config.dev_command = "python app.py".to_string();
            config.http_port = 5000;
        }
        "fastapi" => {
            config.dev_command = "uvicorn main:app --reload".to_string();
            config.http_port = 8000;
        }
        "go" => {
            config.dev_command = "go run .".to_string();
            config.http_port = 8080;
        }
        "rust" => {
            config.dev_command = "cargo run".to_string();
            config.http_port = 3000;
        }
        "java" => {
            config.dev_command = "./mvnw spring-boot:run".to_string();
            config.http_port = 8080;
        }
        "csharp" => {
            config.dev_command = "dotnet run".to_string();
            config.http_port = 5000;
        }
        "php" => {
            config.dev_command = "php -S localhost:8000".to_string();
            config.http_port = 8000;
        }
        "ruby" => {
            config.dev_command = "rails server".to_string();
            config.http_port = 3000;
        }
        _ => {
            // Keep defaults
        }
    }
    
    // Apply project-specific overrides
    if let Some(info) = project_info {
        if let Some(ref dev_cmd) = info.dev_command {
            config.dev_command = dev_cmd.clone();
        }
        
        if let Some(port) = info.port {
            config.http_port = port;
        }
        
        // Add language-specific environment variables
        match info.language {
            Language::Python => {
                config.environment.insert("PYTHONPATH".to_string(), ".".to_string());
            }
            Language::Go => {
                config.environment.insert("GO111MODULE".to_string(), "on".to_string());
            }
            Language::Rust => {
                config.environment.insert("RUST_LOG".to_string(), "debug".to_string());
            }
            Language::Java => {
                config.environment.insert("JAVA_OPTS".to_string(), "-Dspring.profiles.active=dev".to_string());
            }
            Language::CSharp => {
                config.environment.insert("ASPNETCORE_ENVIRONMENT".to_string(), "Development".to_string());
            }
            Language::PHP => {
                config.environment.insert("APP_ENV".to_string(), "development".to_string());
            }
            Language::Ruby => {
                config.environment.insert("RAILS_ENV".to_string(), "development".to_string());
            }
            _ => {}
        }
    }
    
    Ok(config)
}

async fn update_gitignore(project_dir: &PathBuf) -> NebulaResult<()> {
    let gitignore_path = project_dir.join(".gitignore");
    
    let nebula_ignore = "\n# Nebula\n.nebula/\nnebula.log\n*.nebula.pid\n";
    
    if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path).await?;
        if !content.contains("# Nebula") {
            fs::write(&gitignore_path, format!("{}{}", content, nebula_ignore)).await?;
        }
    } else {
        fs::write(&gitignore_path, nebula_ignore).await?;
    }
    
    Ok(())
}

async fn create_nebula_directories(project_dir: &PathBuf) -> NebulaResult<()> {
    let nebula_dir = project_dir.join(".nebula");
    fs::create_dir_all(&nebula_dir).await?;
    
    // Create subdirectories
    fs::create_dir_all(nebula_dir.join("logs")).await?;
    fs::create_dir_all(nebula_dir.join("tmp")).await?;
    
    Ok(())
}

async fn show_project_specific_tips(info: &ProjectInfo) -> NebulaResult<()> {
    info!("💡 Project-specific tips:");
    
    match info.language {
        Language::React | Language::Vue | Language::Angular | Language::Svelte => {
            info!("   • Make sure you have 'npm run dev' or equivalent script in package.json");
            info!("   • Your app will be available at https://{}.nebula.com", 
                  std::env::current_dir()?.file_name().unwrap().to_string_lossy());
        }
        Language::Python => {
            info!("   • Ensure your main application file is named 'app.py' or 'main.py'");
            info!("   • Add your dependencies to requirements.txt");
        }
        Language::Go => {
            info!("   • Make sure you have a go.mod file");
            info!("   • Your main function should be in the root directory");
        }
        Language::Rust => {
            info!("   • Ensure you have a Cargo.toml file");
            info!("   • Your main function should be in src/main.rs");
        }
        _ => {}
    }
    
    Ok(())
}

// Additional helper functions for process management, status checking, etc.
// These would be implemented based on platform-specific requirements

async fn read_pid_file(path: &PathBuf) -> NebulaResult<u32> {
    let content = fs::read_to_string(path).await?;
    content.trim().parse()
        .map_err(|_| NebulaError::config("Invalid PID file format"))
}

async fn write_pid_file(path: &PathBuf, pid: u32) -> NebulaResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(path, pid.to_string()).await?;
    Ok(())
}

fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        
        match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    #[cfg(windows)]
    {
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
        use winapi::um::handleapi::CloseHandle;
        
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
            if handle.is_null() {
                false
            } else {
                CloseHandle(handle);
                true
            }
        }
    }
}

async fn terminate_process(pid: u32, force: bool) -> NebulaResult<bool> {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        
        let signal = if force { Signal::SIGKILL } else { Signal::SIGTERM };
        
        match kill(Pid::from_raw(pid as i32), signal) {
            Ok(_) => {
                // Wait for process to terminate
                for _ in 0..30 {
                    if !is_process_running(pid) {
                        return Ok(true);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Ok(false)
            }
            Err(e) => Err(NebulaError::platform(format!("Failed to terminate process: {}", e))),
        }
    }
    
    #[cfg(windows)]
    {
        use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
        use winapi::um::winnt::PROCESS_TERMINATE;
        use winapi::um::handleapi::CloseHandle;
        
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if handle.is_null() {
                return Err(NebulaError::platform("Failed to open process"));
            }
            
            let result = TerminateProcess(handle, 0);
            CloseHandle(handle);
            
            if result == 0 {
                Err(NebulaError::platform("Failed to terminate process"))
            } else {
                Ok(true)
            }
        }
    }
}

// Status and information display functions would be implemented here
// along with other helper functions for configuration management,
// health checks, etc.

async fn get_server_status() -> NebulaResult<serde_json::Value> {
    // Implementation for getting server status
    Ok(serde_json::json!({}))
}

async fn print_status_text(status: &serde_json::Value) -> NebulaResult<()> {
    // Implementation for printing status in text format
    Ok(())
}

async fn load_current_config() -> NebulaResult<NebulaConfig> {
    let config_path = PathBuf::from("nebula.toml");
    if config_path.exists() {
        NebulaConfig::load_from_file(&config_path).await
    } else {
        Ok(NebulaConfig::default())
    }
}

async fn print_certificates(certs: &[crate::utils::CertificateInfo], format: &str) -> NebulaResult<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(certs)?;
            println!("{}", json);
        }
        "table" | _ => {
            println!("┌─────────────────────────────┬─────────────────────┬─────────────────────┬──────────┐");
            println!("│ Domain                      │ Created             │ Expires             │ Status   │");
            println!("├─────────────────────────────┼─────────────────────┼─────────────────────┼──────────┤");
            
            for cert in certs {
                let status = if cert.expires_at > chrono::Utc::now() {
                    "Valid"
                } else {
                    "Expired"
                };
                
                println!("│ {:27} │ {:19} │ {:19} │ {:8} │",
                    truncate_string(&cert.domain, 27),
                    cert.created_at.format("%Y-%m-%d %H:%M").to_string(),
                    cert.expires_at.format("%Y-%m-%d %H:%M").to_string(),
                    status
                );
            }
            
            println!("└─────────────────────────────┴─────────────────────┴─────────────────────┴──────────┘");
        }
    }
    Ok(())
}

async fn print_dns_records(records: &HashMap<String, Vec<crate::network::dns::DnsRecord>>, format: &str) -> NebulaResult<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(records)?;
            println!("{}", json);
        }
        "table" | _ => {
            println!("┌─────────────────────────────┬──────────┬─────────────────────────────┬─────┐");
            println!("│ Domain                      │ Type     │ Data                        │ TTL │");
            println!("├─────────────────────────────┼──────────┼─────────────────────────────┼─────┤");
            
            for (domain, domain_records) in records {
                for record in domain_records {
                    println!("│ {:27} │ {:8} │ {:27} │ {:3} │",
                        truncate_string(domain, 27),
                        record.record_type.to_string(),
                        truncate_string(&record.data, 27),
                        record.ttl
                    );
                }
            }
            
            println!("└─────────────────────────────┴──────────┴─────────────────────────────┴─────┘");
        }
    }
    Ok(())
}

async fn print_dns_test_result(domain: &str, result: &[String]) -> NebulaResult<()> {
    info!("🧪 DNS Resolution Test for: {}", domain);
    if result.is_empty() {
        info!("❌ No records found");
    } else {
        info!("✅ Resolved to:");
        for record in result {
            info!("   {}", record);
        }
    }
    Ok(())
}

async fn print_dns_statistics(stats: &crate::network::dns::DnsStatistics) -> NebulaResult<()> {
    info!("📊 DNS Server Statistics:");
    info!("   Total Queries: {}", stats.queries_total);
    info!("   Successful: {}", stats.queries_success);
    info!("   Failed: {}", stats.queries_failed);
    info!("   Cache Hits: {}", stats.cache_hits);
    info!("   Cache Misses: {}", stats.cache_misses);
    info!("   Upstream Queries: {}", stats.upstream_queries);
    info!("   Zones: {}", stats.zones_count);
    info!("   Records: {}", stats.records_count);
    Ok(())
}

async fn print_deployments(deployments: &[crate::core::scheduler::Deployment], format: &str) -> NebulaResult<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(deployments)?;
            println!("{}", json);
        }
        "table" | _ => {
            println!("┌──────────────┬─────────────────────────────┬─────────────────────────────┬─────────────┐");
            println!("│ ID           │ Name                        │ Domain                      │ Status      │");
            println!("├──────────────┼─────────────────────────────┼─────────────────────────────┼─────────────┤");
            
            for deployment in deployments {
                println!("│ {:12} │ {:27} │ {:27} │ {:11} │",
                    truncate_string(&deployment.id, 12),
                    truncate_string(&deployment.name, 27),
                    truncate_string(&deployment.domain, 27),
                    format!("{:?}", deployment.status)
                );
            }
            
            println!("└──────────────┴─────────────────────────────┴─────────────────────────────┴─────────────┘");
        }
    }
    Ok(())
}

async fn print_deployment_details(deployment: &crate::core::scheduler::Deployment) -> NebulaResult<()> {
    info!("📊 Deployment Details:");
    info!("   ID: {}", deployment.id);
    info!("   Name: {}", deployment.name);
    info!("   Domain: {}", deployment.domain);
    info!("   Status: {:?}", deployment.status);
    info!("   Created: {}", deployment.created_at);
    info!("   Updated: {}", deployment.updated_at);
    info!("   Port: {}", deployment.config.port);
    info!("   HTTPS: {}", deployment.config.https_enabled);
    info!("   Health Check: {:?}", deployment.config.health_check_path);
    info!("   Environment Variables:");
    for (key, value) in &deployment.config.environment_vars {
        info!("     {}: {}", key, value);
    }
    Ok(())
}

async fn follow_deployment_logs(scheduler: &crate::core::scheduler::NebulaScheduler, deployment_id: &str) -> NebulaResult<()> {
    info!("📝 Following logs for deployment: {}", deployment_id);
    
    // In a real implementation, you'd set up a log stream
    // For now, just show recent logs
    let logs = scheduler.get_deployment_logs(deployment_id, 50).await?;
    for log_line in logs {
        println!("{}", log_line);
    }
    
    info!("Log following not yet implemented");
    Ok(())
}

async fn wait_for_deployment_ready(scheduler: &crate::core::scheduler::NebulaScheduler, deployment_id: &str, timeout: u64) -> NebulaResult<()> {
    use tokio::time::{timeout as tokio_timeout, Duration, sleep};
    
    let result = tokio_timeout(Duration::from_secs(timeout), async {
        loop {
            if let Some(deployment) = scheduler.get_deployment(deployment_id).await {
                match deployment.status {
                    crate::core::scheduler::DeploymentStatus::Running => break,
                    crate::core::scheduler::DeploymentStatus::Failed => {
                        return Err(NebulaError::deployment("Deployment failed to start"));
                    }
                    _ => {
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            } else {
                return Err(NebulaError::not_found("Deployment not found"));
            }
        }
        Ok(())
    }).await;

    match result {
        Ok(Ok(())) => {
            info!("✅ Deployment is ready");
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(NebulaError::timeout("Deployment ready check timed out")),
    }
}

async fn print_config(config: &NebulaConfig, section: Option<&str>, format: &str) -> NebulaResult<()> {
    match format {
        "json" => {
            let json = if let Some(section) = section {
                match section {
                    "server" => serde_json::to_string_pretty(&serde_json::json!({
                        "domain": config.domain,
                        "http_port": config.http_port,
                        "https_port": config.https_port,
                        "dev_command": config.dev_command,
                        "hot_reload": config.hot_reload,
                        "mode": config.mode
                    }))?,
                    "dns" => serde_json::to_string_pretty(&config.dns)?,
                    "dhcp" => serde_json::to_string_pretty(&config.dhcp)?,
                    "tls" => serde_json::to_string_pretty(&config.tls)?,
                    "scheduler" => serde_json::to_string_pretty(&config.scheduler)?,
                    "logging" => serde_json::to_string_pretty(&config.logging)?,
                    "dev" => serde_json::to_string_pretty(&config.dev)?,
                    _ => return Err(NebulaError::validation(format!("Unknown section: {}", section))),
                }
            } else {
                serde_json::to_string_pretty(config)?
            };
            println!("{}", json);
        }
        "toml" | _ => {
            let toml = if let Some(_section) = section {
                // For sections in TOML, we'd need more complex logic
                toml::to_string_pretty(config)?
            } else {
                toml::to_string_pretty(config)?
            };
            println!("{}", toml);
        }
    }
    Ok(())
}

fn set_config_value(config: &mut NebulaConfig, key: &str, value: &str) -> NebulaResult<()> {
    match key {
        "domain" => config.domain = value.to_string(),
        "http_port" => config.http_port = value.parse()?,
        "https_port" => config.https_port = value.parse()?,
        "dev_command" => config.dev_command = value.to_string(),
        "hot_reload" => config.hot_reload = value.parse()?,
        "dns.enabled" => config.dns.enabled = value.parse()?,
        "dhcp.enabled" => config.dhcp.enabled = value.parse()?,
        _ => return Err(NebulaError::validation(format!("Unknown config key: {}", key))),
    }
    Ok(())
}

fn get_config_value(config: &NebulaConfig, key: &str) -> NebulaResult<String> {
    let value = match key {
        "domain" => config.domain.clone(),
        "http_port" => config.http_port.to_string(),
        "https_port" => config.https_port.to_string(),
        "dev_command" => config.dev_command.clone(),
        "hot_reload" => config.hot_reload.to_string(),
        "dns.enabled" => config.dns.enabled.to_string(),
        "dhcp.enabled" => config.dhcp.enabled.to_string(),
        _ => return Err(NebulaError::validation(format!("Unknown config key: {}", key))),
    };
    Ok(value)
}

async fn check_dns_health(timeout: Duration) -> NebulaResult<()> {
    info!("🏥 Checking DNS health...");
    
    // Test DNS resolution
    let test_domains = vec!["app.nebula.com", "google.com"];
    
    for domain in test_domains {
        match tokio::time::timeout(timeout, tokio::net::lookup_host(format!("{}:80", domain))).await {
            Ok(Ok(_)) => info!("✅ DNS resolution working for: {}", domain),
            Ok(Err(e)) => warn!("❌ DNS resolution failed for {}: {}", domain, e),
            Err(_) => warn!("❌ DNS resolution timeout for: {}", domain),
        }
    }
    
    Ok(())
}

async fn check_cert_health(timeout: Duration) -> NebulaResult<()> {
    info!("🏥 Checking certificate health...");
    
    let cert_manager = crate::utils::CertificateManager::new().await?;
    let certs = cert_manager.list_certificates(false).await?;
    
    let mut expired_count = 0;
    let mut expiring_soon_count = 0;
    let now = chrono::Utc::now();
    let threshold = now + chrono::Duration::days(30);
    
    for cert in certs {
        if cert.expires_at < now {
            expired_count += 1;
        } else if cert.expires_at < threshold {
            expiring_soon_count += 1;
        }
    }
    
    if expired_count > 0 {
        warn!("❌ {} certificates have expired", expired_count);
    }
    
    if expiring_soon_count > 0 {
        warn!("⚠️ {} certificates expire within 30 days", expiring_soon_count);
    } else {
        info!("✅ All certificates are healthy");
    }
    
    Ok(())
}

async fn check_server_health(timeout: Duration) -> NebulaResult<()> {
    info!("🏥 Checking server health...");
    
    // Check if server is responding
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()?;
    
    let test_urls = vec![
        "http://127.0.0.1:3000",
        "https://127.0.0.1:3443",
    ];
    
    for url in test_urls {
        match client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("✅ Server responding at: {}", url);
                } else {
                    warn!("⚠️ Server error at {}: {}", url, response.status());
                }
            }
            Err(e) => warn!("❌ Cannot reach server at {}: {}", url, e),
        }
    }
    
    Ok(())
}

async fn clean_directory(dir: &PathBuf) -> NebulaResult<usize> {
    let mut count = 0;
    
    if !dir.exists() {
        return Ok(0);
    }
    
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Err(e) = tokio::fs::remove_file(&path).await {
                warn!("Failed to remove file {:?}: {}", path, e);
            } else {
                count += 1;
            }
        }
    }
    
    Ok(count)
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:width$}", s, width = max_len)
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
