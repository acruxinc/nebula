use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use tracing::{info, debug};

#[derive(Debug, Clone, PartialEq)]
pub enum Language {
    // Frontend Languages
    JavaScript,
    TypeScript,
    React,
    Vue,
    Angular,
    Svelte,
    NextJs,
    NuxtJs,
    
    // Backend Languages
    NodeJs,
    Python,
    Go,
    Rust,
    Java,
    CSharp,
    PHP,
    Ruby,
    Elixir,
    Clojure,
    
    // Compiled Languages
    C,
    Cpp,
    Swift,
    Kotlin,
    
    // Scripting Languages
    Bash,
    PowerShell,
    Lua,
    
    // Other
    Docker,
    Terraform,
    Ansible,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub language: Language,
    pub framework: Option<String>,
    pub package_manager: Option<String>,
    pub build_command: Option<String>,
    pub start_command: Option<String>,
    pub test_command: Option<String>,
    pub dev_command: Option<String>,
    pub port: Option<u16>,
    pub environment: HashMap<String, String>,
}

impl ProjectInfo {
    pub fn new() -> Self {
        Self {
            language: Language::Unknown,
            framework: None,
            package_manager: None,
            build_command: None,
            start_command: None,
            test_command: None,
            dev_command: None,
            port: None,
            environment: HashMap::new(),
        }
    }

    pub fn get_default_dev_command(&self) -> String {
        match self.language {
            Language::JavaScript | Language::NodeJs => {
                if let Some(ref cmd) = self.dev_command {
                    cmd.clone()
                } else if let Some(ref package_manager) = self.package_manager {
                    match package_manager.as_str() {
                        "yarn" => "yarn dev".to_string(),
                        "pnpm" => "pnpm dev".to_string(),
                        _ => "npm run dev".to_string(),
                    }
                } else {
                    "npm run dev".to_string()
                }
            }
            Language::Python => {
                if let Some(ref framework) = self.framework {
                    match framework.as_str() {
                        "flask" => "python app.py".to_string(),
                        "django" => "python manage.py runserver".to_string(),
                        "fastapi" => "uvicorn main:app --reload".to_string(),
                        "streamlit" => "streamlit run app.py".to_string(),
                        _ => "python main.py".to_string(),
                    }
                } else {
                    "python main.py".to_string()
                }
            }
            Language::Go => "go run .".to_string(),
            Language::Rust => "cargo run".to_string(),
            Language::Java => {
                if let Some(ref framework) = self.framework {
                    match framework.as_str() {
                        "spring" => "./mvnw spring-boot:run".to_string(),
                        "quarkus" => "./mvnw compile quarkus:dev".to_string(),
                        _ => "./mvnw spring-boot:run".to_string(),
                    }
                } else {
                    "java -jar target/*.jar".to_string()
                }
            }
            Language::CSharp => {
                if let Some(ref framework) = self.framework {
                    match framework.as_str() {
                        "aspnet" => "dotnet run".to_string(),
                        "blazor" => "dotnet run --project BlazorApp".to_string(),
                        _ => "dotnet run".to_string(),
                    }
                } else {
                    "dotnet run".to_string()
                }
            }
            Language::PHP => {
                if let Some(ref framework) = self.framework {
                    match framework.as_str() {
                        "laravel" => "php artisan serve".to_string(),
                        "symfony" => "symfony serve".to_string(),
                        _ => "php -S localhost:8000".to_string(),
                    }
                } else {
                    "php -S localhost:8000".to_string()
                }
            }
            Language::Ruby => {
                if let Some(ref framework) = self.framework {
                    match framework.as_str() {
                        "rails" => "rails server".to_string(),
                        "sinatra" => "ruby app.rb".to_string(),
                        _ => "ruby app.rb".to_string(),
                    }
                } else {
                    "ruby app.rb".to_string()
                }
            }
            Language::React => "npm start".to_string(),
            Language::Vue => "npm run serve".to_string(),
            Language::Angular => "ng serve".to_string(),
            Language::Svelte => "npm run dev".to_string(),
            Language::NextJs => "npm run dev".to_string(),
            Language::NuxtJs => "npm run dev".to_string(),
            Language::Docker => "docker-compose up".to_string(),
            Language::Bash => "bash script.sh".to_string(),
            Language::PowerShell => "powershell -File script.ps1".to_string(),
            _ => "echo 'No default command available'".to_string(),
        }
    }

    pub fn get_default_port(&self) -> u16 {
        match self.language {
            Language::JavaScript | Language::NodeJs => 3000,
            Language::Python => {
                if let Some(ref framework) = self.framework {
                    match framework.as_str() {
                        "flask" => 5000,
                        "django" => 8000,
                        "fastapi" => 8000,
                        "streamlit" => 8501,
                        _ => 8000,
                    }
                } else {
                    8000
                }
            }
            Language::Go => 8080,
            Language::Rust => 3000,
            Language::Java => 8080,
            Language::CSharp => 5000,
            Language::PHP => 8000,
            Language::Ruby => 3000,
            Language::React => 3000,
            Language::Vue => 8080,
            Language::Angular => 4200,
            Language::Svelte => 5000,
            Language::NextJs => 3000,
            Language::NuxtJs => 3000,
            _ => 3000,
        }
    }
}

pub struct LanguageDetector;

impl LanguageDetector {
    pub fn detect_language(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        
        debug!("Detecting language for project at: {:?}", project_path);
        
        // Check for package.json (Node.js/JavaScript/TypeScript)
        if project_path.join("package.json").exists() {
            project_info = Self::detect_nodejs_project(project_path)?;
        }
        // Check for requirements.txt or pyproject.toml (Python)
        else if project_path.join("requirements.txt").exists() 
            || project_path.join("pyproject.toml").exists()
            || project_path.join("setup.py").exists()
            || project_path.join("Pipfile").exists() {
            project_info = Self::detect_python_project(project_path)?;
        }
        // Check for go.mod (Go)
        else if project_path.join("go.mod").exists() {
            project_info = Self::detect_go_project(project_path)?;
        }
        // Check for Cargo.toml (Rust)
        else if project_path.join("Cargo.toml").exists() {
            project_info = Self::detect_rust_project(project_path)?;
        }
        // Check for pom.xml or build.gradle (Java)
        else if project_path.join("pom.xml").exists() 
            || project_path.join("build.gradle").exists()
            || project_path.join("build.gradle.kts").exists() {
            project_info = Self::detect_java_project(project_path)?;
        }
        // Check for *.csproj or *.sln (C#)
        else if Self::has_csharp_files(project_path) {
            project_info = Self::detect_csharp_project(project_path)?;
        }
        // Check for composer.json (PHP)
        else if project_path.join("composer.json").exists() {
            project_info = Self::detect_php_project(project_path)?;
        }
        // Check for Gemfile (Ruby)
        else if project_path.join("Gemfile").exists() {
            project_info = Self::detect_ruby_project(project_path)?;
        }
        // Check for Dockerfile (Docker)
        else if project_path.join("Dockerfile").exists() 
            || project_path.join("docker-compose.yml").exists() {
            project_info = Self::detect_docker_project(project_path)?;
        }
        // Check for shell scripts
        else if Self::has_shell_scripts(project_path) {
            project_info = Self::detect_shell_project(project_path)?;
        }
        // Check for Terraform files
        else if Self::has_terraform_files(project_path) {
            project_info = Self::detect_terraform_project(project_path)?;
        }
        else {
            // Try to detect by file extensions
            project_info = Self::detect_by_file_extensions(project_path)?;
        }

        info!("Detected project: {:?} with framework: {:?}", 
              project_info.language, project_info.framework);
        
        Ok(project_info)
    }

    fn detect_nodejs_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::NodeJs;
        
        // Read package.json to detect framework and commands
        if let Ok(package_json) = std::fs::read_to_string(project_path.join("package.json")) {
            if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&package_json) {
                // Detect package manager
                if project_path.join("yarn.lock").exists() {
                    project_info.package_manager = Some("yarn".to_string());
                } else if project_path.join("pnpm-lock.yaml").exists() {
                    project_info.package_manager = Some("pnpm".to_string());
                } else {
                    project_info.package_manager = Some("npm".to_string());
                }

                // Detect framework
                if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
                    if deps.contains_key("react") {
                        project_info.language = Language::React;
                        project_info.framework = Some("react".to_string());
                    } else if deps.contains_key("vue") {
                        project_info.language = Language::Vue;
                        project_info.framework = Some("vue".to_string());
                    } else if deps.contains_key("@angular/core") {
                        project_info.language = Language::Angular;
                        project_info.framework = Some("angular".to_string());
                    } else if deps.contains_key("svelte") {
                        project_info.language = Language::Svelte;
                        project_info.framework = Some("svelte".to_string());
                    } else if deps.contains_key("next") {
                        project_info.language = Language::NextJs;
                        project_info.framework = Some("nextjs".to_string());
                    } else if deps.contains_key("nuxt") {
                        project_info.language = Language::NuxtJs;
                        project_info.framework = Some("nuxtjs".to_string());
                    }
                }

                // Extract scripts
                if let Some(scripts) = pkg.get("scripts").and_then(|s| s.as_object()) {
                    project_info.dev_command = scripts.get("dev").and_then(|s| s.as_str()).map(|s| s.to_string());
                    project_info.start_command = scripts.get("start").and_then(|s| s.as_str()).map(|s| s.to_string());
                    project_info.build_command = scripts.get("build").and_then(|s| s.as_str()).map(|s| s.to_string());
                    project_info.test_command = scripts.get("test").and_then(|s| s.as_str()).map(|s| s.to_string());
                }

                // Extract port from scripts or config
                if let Some(scripts) = pkg.get("scripts").and_then(|s| s.as_object()) {
                    for (_, script) in scripts {
                        if let Some(script_str) = script.as_str() {
                            if let Some(port) = Self::extract_port_from_string(script_str) {
                                project_info.port = Some(port);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(project_info)
    }

    fn detect_python_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Python;

        // Detect framework
        if project_path.join("manage.py").exists() {
            project_info.framework = Some("django".to_string());
        } else if project_path.join("app.py").exists() {
            project_info.framework = Some("flask".to_string());
        } else if project_path.join("main.py").exists() {
            // Check for FastAPI
            if let Ok(main_content) = std::fs::read_to_string(project_path.join("main.py")) {
                if main_content.contains("fastapi") || main_content.contains("FastAPI") {
                    project_info.framework = Some("fastapi".to_string());
                }
            }
        }

        // Check for streamlit
        if let Ok(requirements) = std::fs::read_to_string(project_path.join("requirements.txt")) {
            if requirements.contains("streamlit") {
                project_info.framework = Some("streamlit".to_string());
            }
        }

        Ok(project_info)
    }

    fn detect_go_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Go;

        // Check for common Go web frameworks
        if let Ok(go_mod) = std::fs::read_to_string(project_path.join("go.mod")) {
            if go_mod.contains("github.com/gin-gonic/gin") {
                project_info.framework = Some("gin".to_string());
            } else if go_mod.contains("github.com/gorilla/mux") {
                project_info.framework = Some("gorilla".to_string());
            } else if go_mod.contains("github.com/labstack/echo") {
                project_info.framework = Some("echo".to_string());
            }
        }

        Ok(project_info)
    }

    fn detect_rust_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Rust;

        // Check for web frameworks
        if let Ok(cargo_toml) = std::fs::read_to_string(project_path.join("Cargo.toml")) {
            if cargo_toml.contains("actix-web") {
                project_info.framework = Some("actix-web".to_string());
            } else if cargo_toml.contains("axum") {
                project_info.framework = Some("axum".to_string());
            } else if cargo_toml.contains("warp") {
                project_info.framework = Some("warp".to_string());
            } else if cargo_toml.contains("rocket") {
                project_info.framework = Some("rocket".to_string());
            }
        }

        Ok(project_info)
    }

    fn detect_java_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Java;

        // Check for Spring Boot
        if project_path.join("pom.xml").exists() {
            if let Ok(pom_content) = std::fs::read_to_string(project_path.join("pom.xml")) {
                if pom_content.contains("spring-boot-starter") {
                    project_info.framework = Some("spring".to_string());
                }
            }
        }

        // Check for Quarkus
        if project_path.join("pom.xml").exists() {
            if let Ok(pom_content) = std::fs::read_to_string(project_path.join("pom.xml")) {
                if pom_content.contains("quarkus") {
                    project_info.framework = Some("quarkus".to_string());
                }
            }
        }

        Ok(project_info)
    }

    fn detect_csharp_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::CSharp;

        // Check for ASP.NET Core
        if let Ok(csproj_content) = std::fs::read_to_string(
            Self::find_csproj_file(project_path).unwrap_or_else(|| project_path.join("*.csproj"))
        ) {
            if csproj_content.contains("Microsoft.AspNetCore") {
                project_info.framework = Some("aspnet".to_string());
            } else if csproj_content.contains("Microsoft.AspNetCore.Blazor") {
                project_info.framework = Some("blazor".to_string());
            }
        }

        Ok(project_info)
    }

    fn detect_php_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::PHP;

        // Check for Laravel
        if project_path.join("artisan").exists() {
            project_info.framework = Some("laravel".to_string());
        }
        // Check for Symfony
        else if project_path.join("symfony.lock").exists() {
            project_info.framework = Some("symfony".to_string());
        }

        Ok(project_info)
    }

    fn detect_ruby_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Ruby;

        // Check for Rails
        if project_path.join("config.ru").exists() && project_path.join("Gemfile").exists() {
            if let Ok(gemfile_content) = std::fs::read_to_string(project_path.join("Gemfile")) {
                if gemfile_content.contains("rails") {
                    project_info.framework = Some("rails".to_string());
                } else if gemfile_content.contains("sinatra") {
                    project_info.framework = Some("sinatra".to_string());
                }
            }
        }

        Ok(project_info)
    }

    fn detect_docker_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Docker;
        
        // Check for docker-compose
        if project_path.join("docker-compose.yml").exists() {
            project_info.dev_command = Some("docker-compose up".to_string());
        } else if project_path.join("docker-compose.yaml").exists() {
            project_info.dev_command = Some("docker-compose up".to_string());
        } else {
            project_info.dev_command = Some("docker build -t app . && docker run -p 3000:3000 app".to_string());
        }

        Ok(project_info)
    }

    fn detect_shell_project(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        
        if Self::has_powershell_scripts(project_path) {
            project_info.language = Language::PowerShell;
        } else {
            project_info.language = Language::Bash;
        }

        Ok(project_info)
    }

    fn detect_terraform_project(_project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        project_info.language = Language::Terraform;
        project_info.dev_command = Some("terraform plan".to_string());
        Ok(project_info)
    }

    fn detect_by_file_extensions(project_path: &Path) -> Result<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        
        // Count files by extension
        let mut ext_counts: HashMap<String, usize> = HashMap::new();
        
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                if let Some(ext) = entry.path().extension() {
                    if let Some(ext_str) = ext.to_str() {
                        *ext_counts.entry(ext_str.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Determine language by most common extension
        if let Some((ext, _)) = ext_counts.iter().max_by_key(|(_, count)| *count) {
            match ext.as_str() {
                "js" => project_info.language = Language::JavaScript,
                "ts" => project_info.language = Language::TypeScript,
                "py" => project_info.language = Language::Python,
                "go" => project_info.language = Language::Go,
                "rs" => project_info.language = Language::Rust,
                "java" => project_info.language = Language::Java,
                "cs" => project_info.language = Language::CSharp,
                "php" => project_info.language = Language::PHP,
                "rb" => project_info.language = Language::Ruby,
                "cpp" | "cc" | "cxx" => project_info.language = Language::Cpp,
                "c" => project_info.language = Language::C,
                "swift" => project_info.language = Language::Swift,
                "kt" => project_info.language = Language::Kotlin,
                "sh" => project_info.language = Language::Bash,
                "ps1" => project_info.language = Language::PowerShell,
                "lua" => project_info.language = Language::Lua,
                _ => project_info.language = Language::Unknown,
            }
        }

        Ok(project_info)
    }

    fn has_csharp_files(project_path: &Path) -> bool {
        Self::has_files_with_extension(project_path, "csproj")
            || Self::has_files_with_extension(project_path, "sln")
            || Self::has_files_with_extension(project_path, "cs")
    }

    fn has_shell_scripts(project_path: &Path) -> bool {
        Self::has_files_with_extension(project_path, "sh") || Self::has_files_with_extension(project_path, "bash")
    }

    fn has_powershell_scripts(project_path: &Path) -> bool {
        Self::has_files_with_extension(project_path, "ps1")
    }

    fn has_terraform_files(project_path: &Path) -> bool {
        Self::has_files_with_extension(project_path, "tf")
            || Self::has_files_with_extension(project_path, "tfvars")
    }

    fn has_files_with_extension(project_path: &Path, extension: &str) -> bool {
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                if let Some(ext) = entry.path().extension() {
                    if ext == extension {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn find_csproj_file(project_path: &Path) -> Option<std::path::PathBuf> {
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension() == Some(std::ffi::OsStr::new("csproj")) {
                    return Some(path);
                }
            }
        }
        None
    }

    fn extract_port_from_string(s: &str) -> Option<u16> {
        // Look for port patterns like :3000, port 3000, --port=3000, etc.
        let patterns = [
            r":(\d{4,5})",
            r"port\s+(\d{4,5})",
            r"--port[=:](\d{4,5})",
            r"-p\s+(\d{4,5})",
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(s) {
                    if let Some(match_str) = captures.get(1) {
                        if let Ok(port) = match_str.as_str().parse::<u16>() {
                            return Some(port);
                        }
                    }
                }
            }
        }
        None
    }
}

impl Default for ProjectInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_detect_nodejs_project() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path();

        // Create package.json
        std::fs::write(
            project_dir.join("package.json"),
            r#"{
                "name": "test-project",
                "scripts": {
                    "dev": "next dev -p 3000",
                    "build": "next build",
                    "start": "next start"
                },
                "dependencies": {
                    "next": "^13.0.0",
                    "react": "^18.0.0"
                }
            }"#,
        ).unwrap();

        let project_info = LanguageDetector::detect_language(project_dir).unwrap();
        
        assert_eq!(project_info.language, Language::React);
        assert_eq!(project_info.framework, Some("react".to_string()));
        assert_eq!(project_info.dev_command, Some("next dev -p 3000".to_string()));
        assert_eq!(project_info.port, Some(3000));
    }

    #[tokio::test]
    async fn test_detect_python_project() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path();

        // Create requirements.txt
        std::fs::write(
            project_dir.join("requirements.txt"),
            "flask==2.0.0\nrequests==2.28.0",
        ).unwrap();

        // Create app.py
        std::fs::write(
            project_dir.join("app.py"),
            "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef hello():\n    return 'Hello World!'",
        ).unwrap();

        let project_info = LanguageDetector::detect_language(project_dir).unwrap();
        
        assert_eq!(project_info.language, Language::Python);
        assert_eq!(project_info.framework, Some("flask".to_string()));
    }

    #[tokio::test]
    async fn test_detect_go_project() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path();

        // Create go.mod
        std::fs::write(
            project_dir.join("go.mod"),
            "module test-project\n\ngo 1.19\n\nrequire github.com/gin-gonic/gin v1.9.0",
        ).unwrap();

        let project_info = LanguageDetector::detect_language(project_dir).unwrap();
        
        assert_eq!(project_info.language, Language::Go);
        assert_eq!(project_info.framework, Some("gin".to_string()));
    }

    #[tokio::test]
    async fn test_detect_rust_project() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path();

        // Create Cargo.toml
        std::fs::write(
            project_dir.join("Cargo.toml"),
            r#"[package]
name = "test-project"
version = "0.1.0"

[dependencies]
actix-web = "4.0"
tokio = { version = "1.0", features = ["full"] }"#,
        ).unwrap();

        let project_info = LanguageDetector::detect_language(project_dir).unwrap();
        
        assert_eq!(project_info.language, Language::Rust);
        assert_eq!(project_info.framework, Some("actix-web".to_string()));
    }

    #[tokio::test]
    async fn test_default_commands() {
        let mut node_info = ProjectInfo::new();
        node_info.language = Language::NodeJs;
        node_info.package_manager = Some("yarn".to_string());
        
        assert_eq!(node_info.get_default_dev_command(), "yarn dev");

        let mut python_info = ProjectInfo::new();
        python_info.language = Language::Python;
        python_info.framework = Some("flask".to_string());
        
        assert_eq!(python_info.get_default_dev_command(), "python app.py");

        let mut go_info = ProjectInfo::new();
        go_info.language = Language::Go;
        assert_eq!(go_info.get_default_dev_command(), "go run .");
    }
}
