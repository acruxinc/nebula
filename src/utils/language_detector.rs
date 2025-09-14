use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use tracing::{debug, warn};
use serde::{Deserialize, Serialize};

use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    Kotlin,
    Scala,
    
    // Compiled Languages
    C,
    Cpp,
    Swift,
    
    // Scripting Languages
    Bash,
    PowerShell,
    Lua,
    Perl,
    
    // Web Assembly
    WebAssembly,
    
    // Other
    Docker,
    Terraform,
    Ansible,
    Kubernetes,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub language: Language,
    pub framework: Option<String>,
    pub package_manager: Option<String>,
    pub build_tool: Option<String>,
    pub version: Option<String>,
    pub build_command: Option<String>,
    pub start_command: Option<String>,
    pub test_command: Option<String>,
    pub dev_command: Option<String>,
    pub port: Option<u16>,
    pub environment: HashMap<String, String>,
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
    pub scripts: HashMap<String, String>,
    pub confidence: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone)]
struct DetectionRule {
    files: Vec<String>,
    content_patterns: Vec<String>,
    language: Language,
    framework: Option<String>,
    confidence: f32,
}

pub struct LanguageDetector;

impl LanguageDetector {
    pub async fn detect_language(project_path: &Path) -> NebulaResult<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        
        debug!("Detecting language for project at: {:?}", project_path);

        // Initialize detection rules
        let rules = Self::get_detection_rules();
        let mut detection_results = Vec::new();

        // Run all detection rules
        for rule in &rules {
            if let Ok(confidence) = Self::check_rule(project_path, rule).await {
                if confidence > 0.0 {
                    detection_results.push((rule.clone(), confidence));
                }
            }
        }

        // Sort by confidence and select the best match
        detection_results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        if let Some((best_rule, confidence)) = detection_results.first() {
            project_info.language = best_rule.language.clone();
            project_info.framework = best_rule.framework.clone();
            project_info.confidence = *confidence;
            
            // Enhance detection with specific parsers
            project_info = Self::enhance_detection(project_path, project_info).await?;
        } else {
            // Fallback to file extension analysis
            project_info = Self::detect_by_file_extensions(project_path).await?;
        }

        // Post-process to fill in missing information
        project_info = Self::fill_defaults(project_info).await?;

        Ok(project_info)
    }

    fn get_detection_rules() -> Vec<DetectionRule> {
        vec![
            // Node.js projects
            DetectionRule {
                files: vec!["package.json".to_string()],
                content_patterns: vec![],
                language: Language::NodeJs,
                framework: None,
                confidence: 0.9,
            },
            
            // React projects
            DetectionRule {
                files: vec!["package.json".to_string()],
                content_patterns: vec!["\"react\"".to_string()],
                language: Language::React,
                framework: Some("react".to_string()),
                confidence: 0.95,
            },
            
            // Next.js projects
            DetectionRule {
                files: vec!["package.json".to_string(), "next.config.js".to_string()],
                content_patterns: vec!["\"next\"".to_string()],
                language: Language::NextJs,
                framework: Some("nextjs".to_string()),
                confidence: 0.98,
            },
            
            // Vue projects
            DetectionRule {
                files: vec!["package.json".to_string()],
                content_patterns: vec!["\"vue\"".to_string()],
                language: Language::Vue,
                framework: Some("vue".to_string()),
                confidence: 0.95,
            },
            
            // Nuxt.js projects
            DetectionRule {
                files: vec!["nuxt.config.js".to_string(), "nuxt.config.ts".to_string()],
                content_patterns: vec!["\"nuxt\"".to_string()],
                language: Language::NuxtJs,
                framework: Some("nuxtjs".to_string()),
                confidence: 0.98,
            },
            
            // Angular projects
            DetectionRule {
                files: vec!["angular.json".to_string(), "package.json".to_string()],
                content_patterns: vec!["\"@angular/core\"".to_string()],
                language: Language::Angular,
                framework: Some("angular".to_string()),
                confidence: 0.98,
            },
            
            // Svelte projects
            DetectionRule {
                files: vec!["svelte.config.js".to_string(), "package.json".to_string()],
                content_patterns: vec!["\"svelte\"".to_string()],
                language: Language::Svelte,
                framework: Some("svelte".to_string()),
                confidence: 0.95,
            },
            
            // Python projects
            DetectionRule {
                files: vec!["requirements.txt".to_string(), "pyproject.toml".to_string(), "setup.py".to_string()],
                content_patterns: vec![],
                language: Language::Python,
                framework: None,
                confidence: 0.9,
            },
            
            // Django projects
            DetectionRule {
                files: vec!["manage.py".to_string(), "requirements.txt".to_string()],
                content_patterns: vec!["django".to_string()],
                language: Language::Python,
                framework: Some("django".to_string()),
                confidence: 0.95,
            },
            
            // Flask projects
            DetectionRule {
                files: vec!["app.py".to_string(), "requirements.txt".to_string()],
                content_patterns: vec!["flask".to_string()],
                language: Language::Python,
                framework: Some("flask".to_string()),
                confidence: 0.9,
            },
            
            // FastAPI projects
            DetectionRule {
                files: vec!["main.py".to_string(), "requirements.txt".to_string()],
                content_patterns: vec!["fastapi".to_string()],
                language: Language::Python,
                framework: Some("fastapi".to_string()),
                confidence: 0.9,
            },
            
            // Go projects
            DetectionRule {
                files: vec!["go.mod".to_string()],
                content_patterns: vec![],
                language: Language::Go,
                framework: None,
                confidence: 0.95,
            },
            
            // Rust projects
            DetectionRule {
                files: vec!["Cargo.toml".to_string()],
                content_patterns: vec![],
                language: Language::Rust,
                framework: None,
                confidence: 0.95,
            },
            
            // Java projects
            DetectionRule {
                files: vec!["pom.xml".to_string(), "build.gradle".to_string()],
                content_patterns: vec![],
                language: Language::Java,
                framework: None,
                confidence: 0.9,
            },
            
            // Spring Boot projects
            DetectionRule {
                files: vec!["pom.xml".to_string()],
                content_patterns: vec!["spring-boot".to_string()],
                language: Language::Java,
                framework: Some("spring-boot".to_string()),
                confidence: 0.95,
            },
            
            // C# projects
            DetectionRule {
                files: vec!["*.csproj".to_string(), "*.sln".to_string()],
                content_patterns: vec![],
                language: Language::CSharp,
                framework: None,
                confidence: 0.9,
            },
            
            // PHP projects
            DetectionRule {
                files: vec!["composer.json".to_string(), "index.php".to_string()],
                content_patterns: vec![],
                language: Language::PHP,
                framework: None,
                confidence: 0.8,
            },
            
            // Laravel projects
            DetectionRule {
                files: vec!["artisan".to_string(), "composer.json".to_string()],
                content_patterns: vec!["laravel".to_string()],
                language: Language::PHP,
                framework: Some("laravel".to_string()),
                confidence: 0.95,
            },
            
            // Ruby projects
            DetectionRule {
                files: vec!["Gemfile".to_string()],
                content_patterns: vec![],
                language: Language::Ruby,
                framework: None,
                confidence: 0.9,
            },
            
            // Rails projects
            DetectionRule {
                files: vec!["Gemfile".to_string(), "config.ru".to_string()],
                content_patterns: vec!["rails".to_string()],
                language: Language::Ruby,
                framework: Some("rails".to_string()),
                confidence: 0.95,
            },
            
            // Docker projects
            DetectionRule {
                files: vec!["Dockerfile".to_string(), "docker-compose.yml".to_string()],
                content_patterns: vec![],
                language: Language::Docker,
                framework: Some("docker".to_string()),
                confidence: 0.8,
            },
            
            // Terraform projects
            DetectionRule {
                files: vec!["*.tf".to_string(), "terraform.tfvars".to_string()],
                content_patterns: vec![],
                language: Language::Terraform,
                framework: Some("terraform".to_string()),
                confidence: 0.9,
            },
        ]
    }

    async fn check_rule(project_path: &Path, rule: &DetectionRule) -> NebulaResult<f32> {
        let mut file_matches = 0;
        let mut content_matches = 0;

        // Check for required files
        for file_pattern in &rule.files {
            if file_pattern.contains('*') {
                // Handle wildcard patterns
                if Self::has_files_with_pattern(project_path, file_pattern) {
                    file_matches += 1;
                }
            } else if project_path.join(file_pattern).exists() {
                file_matches += 1;
            }
        }

        // If no files match, return 0 confidence
        if file_matches == 0 {
            return Ok(0.0);
        }

        // Check content patterns
        for pattern in &rule.content_patterns {
            if Self::search_for_pattern(project_path, pattern).await? {
                content_matches += 1;
            }
        }

        // Calculate confidence based on matches
        let file_confidence = file_matches as f32 / rule.files.len() as f32;
        let content_confidence = if rule.content_patterns.is_empty() {
            1.0
        } else {
            content_matches as f32 / rule.content_patterns.len() as f32
        };

        let total_confidence = (file_confidence + content_confidence) / 2.0 * rule.confidence;
        Ok(total_confidence)
    }

    fn has_files_with_pattern(project_path: &Path, pattern: &str) -> bool {
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let file_str = file_name.to_string_lossy();
                
                if pattern.starts_with("*.") {
                    let extension = &pattern[2..];
                    if file_str.ends_with(extension) {
                        return true;
                    }
                }
            }
        }
        false
    }

    async fn search_for_pattern(project_path: &Path, pattern: &str) -> NebulaResult<bool> {
        let search_files = ["package.json", "pom.xml", "Cargo.toml", "requirements.txt", "composer.json", "Gemfile"];
        
        for file_name in &search_files {
            let file_path = project_path.join(file_name);
            if file_path.exists() {
                if let Ok(content) = tokio::fs::read_to_string(&file_path).await {
                    if content.contains(pattern) {
                        return Ok(true);
                    }
                }
            }
        }
        
        Ok(false)
    }

    async fn enhance_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        match project_info.language {
            Language::NodeJs | Language::React | Language::Vue | Language::Angular | 
            Language::Svelte | Language::NextJs | Language::NuxtJs => {
                project_info = Self::enhance_nodejs_detection(project_path, project_info).await?;
            }
            Language::Python => {
                project_info = Self::enhance_python_detection(project_path, project_info).await?;
            }
            Language::Go => {
                project_info = Self::enhance_go_detection(project_path, project_info).await?;
            }
            Language::Rust => {
                project_info = Self::enhance_rust_detection(project_path, project_info).await?;
            }
            Language::Java => {
                project_info = Self::enhance_java_detection(project_path, project_info).await?;
            }
            Language::CSharp => {
                project_info = Self::enhance_csharp_detection(project_path, project_info).await?;
            }
            Language::PHP => {
                project_info = Self::enhance_php_detection(project_path, project_info).await?;
            }
            Language::Ruby => {
                project_info = Self::enhance_ruby_detection(project_path, project_info).await?;
            }
            _ => {}
        }

        Ok(project_info)
    }

    async fn enhance_nodejs_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        let package_json_path = project_path.join("package.json");
        if !package_json_path.exists() {
            return Ok(project_info);
        }

        let content = tokio::fs::read_to_string(&package_json_path).await?;
        let package_json: serde_json::Value = serde_json::from_str(&content)?;

        // Detect package manager
        if project_path.join("yarn.lock").exists() {
            project_info.package_manager = Some("yarn".to_string());
        } else if project_path.join("pnpm-lock.yaml").exists() {
            project_info.package_manager = Some("pnpm".to_string());
        } else if project_path.join("package-lock.json").exists() {
            project_info.package_manager = Some("npm".to_string());
        } else {
            project_info.package_manager = Some("npm".to_string());
        }

        // Extract version
        if let Some(version) = package_json.get("version").and_then(|v| v.as_str()) {
            project_info.version = Some(version.to_string());
        }

        // Extract scripts
        if let Some(scripts) = package_json.get("scripts").and_then(|s| s.as_object()) {
            for (key, value) in scripts {
                if let Some(command) = value.as_str() {
                    project_info.scripts.insert(key.clone(), command.to_string());
                    
                    match key.as_str() {
                        "dev" | "develop" | "start:dev" => {
                            project_info.dev_command = Some(command.to_string());
                        }
                        "start" => {
                            project_info.start_command = Some(command.to_string());
                        }
                        "test" => {
                            project_info.test_command = Some(command.to_string());
                        }
                        "build" => {
                            project_info.build_command = Some(command.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }

        // Extract dependencies
        if let Some(deps) = package_json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, _) in deps {
                project_info.dependencies.push(name.clone());
            }
        }

        if let Some(dev_deps) = package_json.get("devDependencies").and_then(|d| d.as_object()) {
            for (name, _) in dev_deps {
                project_info.dev_dependencies.push(name.clone());
            }
        }

        // Detect specific frameworks based on dependencies
        let deps_str = project_info.dependencies.join(" ");
        let dev_deps_str = project_info.dev_dependencies.join(" ");
        let all_deps = format!("{} {}", deps_str, dev_deps_str);

        if all_deps.contains("next") && project_info.language != Language::NextJs {
            project_info.language = Language::NextJs;
            project_info.framework = Some("nextjs".to_string());
        } else if all_deps.contains("nuxt") && project_info.language != Language::NuxtJs {
            project_info.language = Language::NuxtJs;
            project_info.framework = Some("nuxtjs".to_string());
        } else if all_deps.contains("react") && project_info.language != Language::React {
            project_info.language = Language::React;
            project_info.framework = Some("react".to_string());
        } else if all_deps.contains("vue") && project_info.language != Language::Vue {
            project_info.language = Language::Vue;
            project_info.framework = Some("vue".to_string());
        } else if all_deps.contains("@angular/core") && project_info.language != Language::Angular {
            project_info.language = Language::Angular;
            project_info.framework = Some("angular".to_string());
        } else if all_deps.contains("svelte") && project_info.language != Language::Svelte {
            project_info.language = Language::Svelte;
            project_info.framework = Some("svelte".to_string());
        }

        // Extract port from scripts
        for script in project_info.scripts.values() {
            if let Some(port) = Self::extract_port_from_command(script) {
                project_info.port = Some(port);
                break;
            }
        }

        Ok(project_info)
    }

    async fn enhance_python_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        // Check for Django
        if project_path.join("manage.py").exists() {
            project_info.framework = Some("django".to_string());
            project_info.dev_command = Some("python manage.py runserver".to_string());
            project_info.port = Some(8000);
        }
        // Check for Flask
        else if project_path.join("app.py").exists() || project_path.join("main.py").exists() {
            let app_file = if project_path.join("app.py").exists() { "app.py" } else { "main.py" };
            
            if let Ok(content) = tokio::fs::read_to_string(project_path.join(app_file)).await {
                if content.contains("from flask") || content.contains("import flask") {
                    project_info.framework = Some("flask".to_string());
                    project_info.dev_command = Some(format!("python {}", app_file));
                    project_info.port = Some(5000);
                } else if content.contains("fastapi") || content.contains("FastAPI") {
                    project_info.framework = Some("fastapi".to_string());
                    project_info.dev_command = Some("uvicorn main:app --reload".to_string());
                    project_info.port = Some(8000);
                }
            }
        }

        // Check for package managers
        if project_path.join("Pipfile").exists() {
            project_info.package_manager = Some("pipenv".to_string());
        } else if project_path.join("poetry.lock").exists() {
            project_info.package_manager = Some("poetry".to_string());
        } else if project_path.join("requirements.txt").exists() {
            project_info.package_manager = Some("pip".to_string());
        }

        // Parse requirements.txt
        if let Ok(content) = tokio::fs::read_to_string(project_path.join("requirements.txt")).await {
            for line in content.lines() {
                let dep = line.split("==").next().unwrap_or(line).trim();
                if !dep.is_empty() && !dep.starts_with('#') {
                    project_info.dependencies.push(dep.to_string());
                }
            }
        }

        Ok(project_info)
    }

    async fn enhance_go_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        let go_mod_path = project_path.join("go.mod");
        if let Ok(content) = tokio::fs::read_to_string(&go_mod_path).await {
            // Extract module name and Go version
            for line in content.lines() {
                if line.starts_with("module ") {
                    project_info.dependencies.push(line.replace("module ", ""));
                } else if line.starts_with("go ") {
                    project_info.version = Some(line.replace("go ", ""));
                } else if line.trim().starts_with("github.com/gin-gonic/gin") {
                    project_info.framework = Some("gin".to_string());
                } else if line.trim().starts_with("github.com/labstack/echo") {
                    project_info.framework = Some("echo".to_string());
                } else if line.trim().starts_with("github.com/gorilla/mux") {
                    project_info.framework = Some("gorilla-mux".to_string());
                }
            }
        }

        project_info.dev_command = Some("go run .".to_string());
        project_info.build_command = Some("go build".to_string());
        project_info.port = Some(8080);

        Ok(project_info)
    }

    async fn enhance_rust_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        let cargo_toml_path = project_path.join("Cargo.toml");
        if let Ok(content) = tokio::fs::read_to_string(&cargo_toml_path).await {
            if let Ok(cargo_toml) = toml::from_str::<toml::Value>(&content) {
                // Extract version
                if let Some(version) = cargo_toml.get("package").and_then(|p| p.get("version")).and_then(|v| v.as_str()) {
                    project_info.version = Some(version.to_string());
                }

                // Extract dependencies
                if let Some(deps) = cargo_toml.get("dependencies").and_then(|d| d.as_table()) {
                    for (name, _) in deps {
                        project_info.dependencies.push(name.clone());
                        
                        // Detect web frameworks
                        match name.as_str() {
                            "actix-web" => project_info.framework = Some("actix-web".to_string()),
                            "axum" => project_info.framework = Some("axum".to_string()),
                            "warp" => project_info.framework = Some("warp".to_string()),
                            "rocket" => project_info.framework = Some("rocket".to_string()),
                            _ => {}
                        }
                    }
                }
            }
        }

        project_info.dev_command = Some("cargo run".to_string());
        project_info.build_command = Some("cargo build --release".to_string());
        project_info.test_command = Some("cargo test".to_string());
        project_info.port = Some(3000);

        Ok(project_info)
    }

    async fn enhance_java_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        // Check for Maven
        if project_path.join("pom.xml").exists() {
            project_info.build_tool = Some("maven".to_string());
            project_info.build_command = Some("mvn compile".to_string());
            project_info.test_command = Some("mvn test".to_string());
            
            if let Ok(content) = tokio::fs::read_to_string(project_path.join("pom.xml")).await {
                if content.contains("spring-boot") {
                    project_info.framework = Some("spring-boot".to_string());
                    project_info.dev_command = Some("mvn spring-boot:run".to_string());
                    project_info.port = Some(8080);
                }
            }
        }
        // Check for Gradle
        else if project_path.join("build.gradle").exists() || project_path.join("build.gradle.kts").exists() {
            project_info.build_tool = Some("gradle".to_string());
            project_info.build_command = Some("./gradlew build".to_string());
            project_info.test_command = Some("./gradlew test".to_string());
        }

        Ok(project_info)
    }

    async fn enhance_csharp_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        // Find .csproj files
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let file_str = file_name.to_string_lossy();
                
                if file_str.ends_with(".csproj") {
                    if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                        if content.contains("Microsoft.AspNetCore") {
                            project_info.framework = Some("aspnet-core".to_string());
                            project_info.port = Some(5000);
                        }
                    }
                }
            }
        }

        project_info.dev_command = Some("dotnet run".to_string());
        project_info.build_command = Some("dotnet build".to_string());
        project_info.test_command = Some("dotnet test".to_string());

        Ok(project_info)
    }

    async fn enhance_php_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        if project_path.join("artisan").exists() {
            project_info.framework = Some("laravel".to_string());
            project_info.dev_command = Some("php artisan serve".to_string());
        } else if project_path.join("bin/console").exists() {
            project_info.framework = Some("symfony".to_string());
            project_info.dev_command = Some("symfony serve".to_string());
        } else {
            project_info.dev_command = Some("php -S localhost:8000".to_string());
        }

        project_info.port = Some(8000);
        Ok(project_info)
    }

    async fn enhance_ruby_detection(project_path: &Path, mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        if project_path.join("config.ru").exists() {
            if let Ok(content) = tokio::fs::read_to_string(project_path.join("Gemfile")).await {
                if content.contains("rails") {
                    project_info.framework = Some("rails".to_string());
                    project_info.dev_command = Some("rails server".to_string());
                } else if content.contains("sinatra") {
                    project_info.framework = Some("sinatra".to_string());
                    project_info.dev_command = Some("ruby app.rb".to_string());
                }
            }
        }

        project_info.port = Some(3000);
        Ok(project_info)
    }

    async fn detect_by_file_extensions(project_path: &Path) -> NebulaResult<ProjectInfo> {
        let mut project_info = ProjectInfo::new();
        let mut ext_counts: HashMap<String, usize> = HashMap::new();
        
        // Count files by extension
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                if let Some(ext) = entry.path().extension() {
                    if let Some(ext_str) = ext.to_str() {
                        *ext_counts.entry(ext_str.to_lowercase()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Determine language by most common extension
        if let Some((ext, _)) = ext_counts.iter().max_by_key(|(_, count)| *count) {
            project_info.language = match ext.as_str() {
                "js" => Language::JavaScript,
                "ts" => Language::TypeScript,
                "py" => Language::Python,
                "go" => Language::Go,
                "rs" => Language::Rust,
                "java" => Language::Java,
                "cs" => Language::CSharp,
                "php" => Language::PHP,
                "rb" => Language::Ruby,
                "cpp" | "cc" | "cxx" => Language::Cpp,
                "c" => Language::C,
                "swift" => Language::Swift,
                "kt" => Language::Kotlin,
                "scala" => Language::Scala,
                "sh" => Language::Bash,
                "ps1" => Language::PowerShell,
                "lua" => Language::Lua,
                "pl" => Language::Perl,
                _ => Language::Unknown,
            };
            
            project_info.confidence = 0.5; // Lower confidence for extension-only detection
        }

        Ok(project_info)
    }

    async fn fill_defaults(mut project_info: ProjectInfo) -> NebulaResult<ProjectInfo> {
        // Set default commands if not already set
        if project_info.dev_command.is_none() {
            project_info.dev_command = Some(project_info.get_default_dev_command());
        }

        if project_info.port.is_none() {
            project_info.port = Some(project_info.get_default_port());
        }

        // Add language-specific environment variables
        match project_info.language {
            Language::Python => {
                project_info.environment.insert("PYTHONPATH".to_string(), ".".to_string());
                project_info.environment.insert("PYTHONUNBUFFERED".to_string(), "1".to_string());
            }
            Language::Go => {
                project_info.environment.insert("GO111MODULE".to_string(), "on".to_string());
            }
            Language::Rust => {
                project_info.environment.insert("RUST_LOG".to_string(), "debug".to_string());
                project_info.environment.insert("RUST_BACKTRACE".to_string(), "1".to_string());
            }
            Language::Java => {
                project_info.environment.insert("JAVA_OPTS".to_string(), "-Dspring.profiles.active=dev".to_string());
            }
            Language::CSharp => {
                project_info.environment.insert("ASPNETCORE_ENVIRONMENT".to_string(), "Development".to_string());
            }
            Language::PHP => {
                project_info.environment.insert("APP_ENV".to_string(), "development".to_string());
            }
            Language::Ruby => {
                project_info.environment.insert("RAILS_ENV".to_string(), "development".to_string());
            }
            Language::NodeJs | Language::React | Language::Vue | Language::Angular | 
            Language::Svelte | Language::NextJs | Language::NuxtJs => {
                project_info.environment.insert("NODE_ENV".to_string(), "development".to_string());
            }
            _ => {}
        }

        Ok(project_info)
    }

    fn extract_port_from_command(command: &str) -> Option<u16> {
        // Common port patterns in commands
        let patterns = [
            r":(\d{4,5})",           // :3000
            r"port[=:\s]+(\d{4,5})", // port=3000, port:3000, port 3000
            r"-p\s+(\d{4,5})",       // -p 3000
            r"--port[=:\s]+(\d{4,5})", // --port=3000
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(command) {
                    if let Some(match_str) = captures.get(1) {
                        if let Ok(port) = match_str.as_str().parse::<u16>() {
                            if port >= 1024 && port <= 65535 {
                                return Some(port);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

impl ProjectInfo {
    pub fn new() -> Self {
        Self {
            language: Language::Unknown,
            framework: None,
            package_manager: None,
            build_tool: None,
            version: None,
            build_command: None,
            start_command: None,
            test_command: None,
            dev_command: None,
            port: None,
            environment: HashMap::new(),
            dependencies: Vec::new(),
            dev_dependencies: Vec::new(),
            scripts: HashMap::new(),
            confidence: 0.0,
        }
    }

    pub fn get_default_dev_command(&self) -> String {
        match self.language {
            Language::JavaScript | Language::NodeJs => {
                if let Some(ref pm) = self.package_manager {
                    match pm.as_str() {
                        "yarn" => "yarn dev".to_string(),
                        "pnpm" => "pnpm dev".to_string(),
                        _ => "npm run dev".to_string(),
                    }
                } else {
                    "npm run dev".to_string()
                }
            }
            Language::React => "npm start".to_string(),
            Language::Vue => "npm run serve".to_string(),
            Language::Angular => "ng serve".to_string(),
            Language::Svelte => "npm run dev".to_string(),
            Language::NextJs => "npm run dev".to_string(),
            Language::NuxtJs => "npm run dev".to_string(),
            Language::Python => {
                match self.framework.as_ref().map(|s| s.as_str()) {
                    Some("django") => "python manage.py runserver".to_string(),
                    Some("flask") => "python app.py".to_string(),
                    Some("fastapi") => "uvicorn main:app --reload".to_string(),
                    _ => "python main.py".to_string(),
                }
            }
            Language::Go => "go run .".to_string(),
            Language::Rust => "cargo run".to_string(),
            Language::Java => {
                match self.build_tool.as_ref().map(|s| s.as_str()) {
                    Some("maven") => "./mvnw spring-boot:run".to_string(),
                    Some("gradle") => "./gradlew bootRun".to_string(),
                    _ => "java -jar target/*.jar".to_string(),
                }
            }
            Language::CSharp => "dotnet run".to_string(),
            Language::PHP => {
                match self.framework.as_ref().map(|s| s.as_str()) {
                    Some("laravel") => "php artisan serve".to_string(),
                    Some("symfony") => "symfony serve".to_string(),
                    _ => "php -S localhost:8000".to_string(),
                }
            }
            Language::Ruby => {
                match self.framework.as_ref().map(|s| s.as_str()) {
                    Some("rails") => "rails server".to_string(),
                    Some("sinatra") => "ruby app.rb".to_string(),
                    _ => "ruby app.rb".to_string(),
                }
            }
            Language::Docker => "docker-compose up".to_string(),
            Language::Terraform => "terraform apply".to_string(),
            _ => "echo 'No default command available'".to_string(),
        }
    }

    pub fn get_default_port(&self) -> u16 {
        match self.language {
            Language::JavaScript | Language::NodeJs | Language::React | 
            Language::NextJs | Language::NuxtJs | Language::Rust => 3000,
            Language::Vue => 8080,
            Language::Angular => 4200,
            Language::Svelte => 5000,
            Language::Python => {
                match self.framework.as_ref().map(|s| s.as_str()) {
                    Some("flask") => 5000,
                    Some("django") | Some("fastapi") => 8000,
                    _ => 8000,
                }
            }
            Language::Go | Language::Java | Language::PHP => 8080,
            Language::CSharp => 5000,
            Language::Ruby => 3000,
            _ => 3000,
        }
    }

    pub fn is_web_project(&self) -> bool {
        matches!(self.language, 
            Language::JavaScript | Language::TypeScript | Language::React | 
            Language::Vue | Language::Angular | Language::Svelte | 
            Language::NextJs | Language::NuxtJs | Language::NodeJs
        ) || 
        matches!(self.framework.as_ref().map(|s| s.as_str()), 
            Some("django") | Some("flask") | Some("fastapi") | 
            Some("spring-boot") | Some("aspnet-core") | 
            Some("laravel") | Some("symfony") | Some("rails")
        )
    }

    pub fn supports_hot_reload(&self) -> bool {
        match self.language {
            Language::React | Language::Vue | Language::Angular | Language::Svelte |
            Language::NextJs | Language::NuxtJs | Language::JavaScript | Language::TypeScript => true,
            Language::Python => {
                matches!(self.framework.as_ref().map(|s| s.as_str()), 
                    Some("django") | Some("flask") | Some("fastapi"))
            }
            Language::Go | Language::Rust => false, // Requires external tools
            Language::Java => {
                matches!(self.framework.as_ref().map(|s| s.as_str()), Some("spring-boot"))
            }
            Language::CSharp => true, // .NET Core supports hot reload
            Language::PHP => true,
            Language::Ruby => {
                matches!(self.framework.as_ref().map(|s| s.as_str()), Some("rails"))
            }
            _ => false,
        }
    }
}

impl Default for ProjectInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::JavaScript => write!(f, "JavaScript"),
            Language::TypeScript => write!(f, "TypeScript"),
            Language::React => write!(f, "React"),
            Language::Vue => write!(f, "Vue.js"),
            Language::Angular => write!(f, "Angular"),
            Language::Svelte => write!(f, "Svelte"),
            Language::NextJs => write!(f, "Next.js"),
            Language::NuxtJs => write!(f, "Nuxt.js"),
            Language::NodeJs => write!(f, "Node.js"),
            Language::Python => write!(f, "Python"),
            Language::Go => write!(f, "Go"),
            Language::Rust => write!(f, "Rust"),
            Language::Java => write!(f, "Java"),
            Language::CSharp => write!(f, "C#"),
            Language::PHP => write!(f, "PHP"),
            Language::Ruby => write!(f, "Ruby"),
            Language::Elixir => write!(f, "Elixir"),
            Language::Clojure => write!(f, "Clojure"),
            Language::Kotlin => write!(f, "Kotlin"),
            Language::Scala => write!(f, "Scala"),
            Language::C => write!(f, "C"),
            Language::Cpp => write!(f, "C++"),
            Language::Swift => write!(f, "Swift"),
            Language::Bash => write!(f, "Bash"),
            Language::PowerShell => write!(f, "PowerShell"),
            Language::Lua => write!(f, "Lua"),
            Language::Perl => write!(f, "Perl"),
            Language::WebAssembly => write!(f, "WebAssembly"),
            Language::Docker => write!(f, "Docker"),
            Language::Terraform => write!(f, "Terraform"),
            Language::Ansible => write!(f, "Ansible"),
            Language::Kubernetes => write!(f, "Kubernetes"),
            Language::Unknown => write!(f, "Unknown"),
        }
    }
}
