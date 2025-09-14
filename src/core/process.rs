use anyhow::Result;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn, error};
use std::collections::HashMap;

pub struct DevProcess {
    command: String,
    working_dir: Option<PathBuf>,
    env_vars: HashMap<String, String>,
}

impl DevProcess {
    pub fn new(command: &str, working_dir: Option<PathBuf>) -> Result<Self> {
        Ok(Self {
            command: command.to_string(),
            working_dir,
            env_vars: HashMap::new(),
        })
    }

    pub fn add_env_var(&mut self, key: String, value: String) {
        self.env_vars.insert(key, value);
    }

    pub fn add_env_vars(&mut self, vars: HashMap<String, String>) {
        self.env_vars.extend(vars);
    }

    pub async fn start(&self) -> Result<ProcessHandle> {
        info!("🚀 Starting development command: {}", self.command);

        let parts: Vec<&str> = self.command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow::anyhow!("Empty command"));
        }

        let mut cmd = Command::new(parts[0]);
        
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        if let Some(dir) = &self.working_dir {
            cmd.current_dir(dir);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        // Set up stdio for streaming output
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .stdin(Stdio::null());

        let mut child = cmd.spawn()?;

        // Stream stdout
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            tokio::spawn(async move {
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    println!("[DEV] {}", line);
                }
            });
        }

        // Stream stderr
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            tokio::spawn(async move {
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    eprintln!("[DEV] {}", line);
                }
            });
        }

        Ok(ProcessHandle::new(child))
    }
}

pub struct ProcessHandle {
    child: Child,
}

impl ProcessHandle {
    fn new(child: Child) -> Self {
        Self { child }
    }

    pub async fn wait(&mut self) -> Result<()> {
        match self.child.wait().await {
            Ok(status) => {
                if status.success() {
                    info!("✅ Development process completed successfully");
                } else {
                    error!("❌ Development process exited with error: {}", status);
                }
                Ok(())
            }
            Err(e) => {
                error!("Failed to wait for process: {}", e);
                Err(e.into())
            }
        }
    }

    pub async fn kill(&mut self) -> Result<()> {
        info!("🛑 Terminating development process...");
        self.child.kill().await?;
        Ok(())
    }

    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }
}

#[cfg(unix)]
pub async fn write_pid_file(pid: u32) -> Result<()> {
    use std::fs;
    
    let nebula_dir = PathBuf::from(".nebula");
    fs::create_dir_all(&nebula_dir)?;
    
    let pid_file = nebula_dir.join("nebula.pid");
    fs::write(pid_file, pid.to_string())?;
    
    Ok(())
}

#[cfg(windows)]
pub async fn write_pid_file(pid: u32) -> Result<()> {
    use std::fs;
    
    let nebula_dir = PathBuf::from(".nebula");
    fs::create_dir_all(&nebula_dir)?;
    
    let pid_file = nebula_dir.join("nebula.pid");
    fs::write(pid_file, pid.to_string())?;
    
    Ok(())
}
