use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::io::{AsyncBufReadExt, BufReader, AsyncRead};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, warn, debug};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Debug)]
pub struct DevProcess {
    command: String,
    working_dir: PathBuf,
    env_vars: HashMap<String, String>,
    current_handle: Option<ProcessHandle>,
    restart_count: u32,
    last_start: Option<Instant>,
    output_tx: Option<mpsc::UnboundedSender<ProcessOutput>>,
}

#[derive(Debug)]
pub struct ProcessHandle {
    child: Child,
    pid: Option<u32>,
    stdout_handle: Option<tokio::task::JoinHandle<()>>,
    stderr_handle: Option<tokio::task::JoinHandle<()>>,
    start_time: Instant,
}

#[derive(Debug, Clone)]
pub struct ProcessOutput {
    pub stream: OutputStream,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone)]
pub struct ProcessStats {
    pub pid: Option<u32>,
    pub start_time: Option<Instant>,
    pub restart_count: u32,
    pub last_restart: Option<Instant>,
    pub is_running: bool,
    pub uptime: Option<Duration>,
}

impl DevProcess {
    pub async fn new(
        command: &str,
        working_dir: PathBuf,
        env_vars: HashMap<String, String>,
    ) -> NebulaResult<Self> {
        if command.is_empty() {
            return Err(NebulaError::validation("Command cannot be empty"));
        }

        if !working_dir.exists() {
            return Err(NebulaError::file_not_found(format!("Working directory does not exist: {:?}", working_dir)));
        }

        let (output_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            command: command.to_string(),
            working_dir,
            env_vars,
            current_handle: None,
            restart_count: 0,
            last_start: None,
            output_tx: Some(output_tx),
        })
    }

    pub async fn start(&mut self) -> NebulaResult<()> {
        if self.is_running() {
            return Err(NebulaError::already_exists("Process is already running"));
        }

        info!("🚀 Starting development command: {}", self.command);
        debug!("Working directory: {:?}", self.working_dir);
        debug!("Environment variables: {:?}", self.env_vars);

        let parts = self.parse_command(&self.command)?;
        if parts.is_empty() {
            return Err(NebulaError::validation("Empty command after parsing"));
        }

        let mut cmd = Command::new(&parts[0]);
        
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        cmd.current_dir(&self.working_dir);

        // Set environment variables
        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        // Configure stdio
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .stdin(Stdio::null())
           .kill_on_drop(true);

        let mut child = cmd.spawn()
            .map_err(|e| NebulaError::command_failed(format!("Failed to spawn process '{}': {}", self.command, e)))?;

        let pid = child.id();
        let start_time = Instant::now();

        // Set up output streaming
        let stdout_handle = if let Some(stdout) = child.stdout.take() {
            Some(self.spawn_output_reader(stdout, OutputStream::Stdout).await)
        } else {
            None
        };

        let stderr_handle = if let Some(stderr) = child.stderr.take() {
            Some(self.spawn_output_reader(stderr, OutputStream::Stderr).await)
        } else {
            None
        };

        let handle = ProcessHandle {
            child,
            pid,
            stdout_handle,
            stderr_handle,
            start_time,
        };

        self.current_handle = Some(handle);
        self.last_start = Some(start_time);

        info!("✅ Development process started with PID: {:?}", pid);
        Ok(())
    }

    pub async fn stop(&mut self) -> NebulaResult<()> {
        if let Some(mut handle) = self.current_handle.take() {
            info!("🛑 Stopping development process (PID: {:?})", handle.pid);
            
            // Try graceful shutdown first
            #[cfg(unix)]
            {
                if let Some(pid) = handle.pid {
                    use nix::sys::signal::{Signal, kill};
                    use nix::unistd::Pid;
                    
                    if let Err(e) = kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                        warn!("Failed to send SIGTERM to process {}: {}", pid, e);
                    } else {
                        // Wait for graceful shutdown
                        for _ in 0..50 { // 5 seconds
                            if handle.child.try_wait()?.is_some() {
                                info!("Process terminated gracefully");
                                return Ok(());
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }

            // Force kill if graceful shutdown failed
            handle.child.kill().await
                .map_err(|e| NebulaError::command_failed(format!("Failed to kill process: {}", e)))?;

            // Wait for the process to exit
            let exit_status = handle.child.wait().await
                .map_err(|e| NebulaError::command_failed(format!("Failed to wait for process: {}", e)))?;

            // Cancel output handles
            if let Some(stdout_handle) = handle.stdout_handle {
                stdout_handle.abort();
            }
            if let Some(stderr_handle) = handle.stderr_handle {
                stderr_handle.abort();
            }

            info!("✅ Development process stopped with exit code: {:?}", exit_status.code());
        } else {
            warn!("No running process to stop");
        }

        Ok(())
    }

    pub async fn restart(&mut self) -> NebulaResult<()> {
        info!("🔄 Restarting development process...");
        
        if self.is_running() {
            self.stop().await?;
        }

        // Small delay before restart
        tokio::time::sleep(Duration::from_millis(500)).await;

        self.restart_count += 1;
        self.start().await?;

        info!("✅ Development process restarted (restart count: {})", self.restart_count);
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        if let Some(ref handle) = self.current_handle {
            // Try to check if the process is still alive without waiting
            match handle.child.try_wait() {
                Ok(Some(_)) => false, // Process has exited
                Ok(None) => true,     // Process is still running
                Err(_) => false,      // Error occurred, assume not running
            }
        } else {
            false
        }
    }

    pub fn get_pid(&self) -> Option<u32> {
        self.current_handle.as_ref().and_then(|h| h.pid)
    }

    pub fn get_stats(&self) -> ProcessStats {
        ProcessStats {
            pid: self.get_pid(),
            start_time: self.last_start,
            restart_count: self.restart_count,
            last_restart: if self.restart_count > 0 { self.last_start } else { None },
            is_running: self.is_running(),
            uptime: self.last_start.map(|start| start.elapsed()),
        }
    }

    pub fn subscribe_output(&self) -> mpsc::UnboundedReceiver<ProcessOutput> {
        let (tx, rx) = mpsc::unbounded_channel();
        // In a real implementation, you'd manage multiple subscribers
        rx
    }

    async fn spawn_output_reader<T>(&self, reader: T, stream: OutputStream) -> tokio::task::JoinHandle<()>
    where
        T: AsyncRead + Unpin + Send + 'static,
    {
        let output_tx = self.output_tx.clone();
        
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            
            while let Ok(Some(line)) = lines.next_line().await {
                let output = ProcessOutput {
                    stream: stream.clone(),
                    content: line.clone(),
                    timestamp: chrono::Utc::now(),
                };

                // Print to console with prefix
                match stream {
                    OutputStream::Stdout => println!("[DEV] {}", line),
                    OutputStream::Stderr => eprintln!("[DEV] {}", line),
                }

                // Send to subscribers
                if let Some(ref tx) = output_tx {
                    let _ = tx.send(output);
                }
            }
        })
    }

    fn parse_command(&self, command: &str) -> NebulaResult<Vec<String>> {
        // Simple command parsing - in production you might want to use shell-words crate
        let parts: Vec<String> = if cfg!(windows) {
            // On Windows, handle cmd.exe /c "command"
            if command.contains(' ') && !command.starts_with('"') {
                vec!["cmd".to_string(), "/c".to_string(), command.to_string()]
            } else {
                shell_words::split(command)
                    .map_err(|e| NebulaError::validation(format!("Failed to parse command: {}", e)))?
            }
        } else {
            shell_words::split(command)
                .map_err(|e| NebulaError::validation(format!("Failed to parse command: {}", e)))?
        };

        if parts.is_empty() {
            return Err(NebulaError::validation("Command parsing resulted in empty command"));
        }

        // Validate that the command exists
        if which::which(&parts[0]).is_err() {
            return Err(NebulaError::command_failed(format!("Command not found: {}", parts[0])));
        }

        Ok(parts)
    }

    pub async fn wait_for_exit(&mut self) -> NebulaResult<std::process::ExitStatus> {
        if let Some(ref mut handle) = self.current_handle {
            let exit_status = handle.child.wait().await
                .map_err(|e| NebulaError::command_failed(format!("Failed to wait for process: {}", e)))?;
            
            // Clean up handles
            if let Some(stdout_handle) = handle.stdout_handle.take() {
                stdout_handle.abort();
            }
            if let Some(stderr_handle) = handle.stderr_handle.take() {
                stderr_handle.abort();
            }

            self.current_handle = None;
            Ok(exit_status)
        } else {
            Err(NebulaError::not_found("No running process to wait for"))
        }
    }

    pub fn set_env_var(&mut self, key: String, value: String) {
        self.env_vars.insert(key, value);
    }

    pub fn remove_env_var(&mut self, key: &str) {
        self.env_vars.remove(key);
    }

    pub fn get_env_vars(&self) -> &HashMap<String, String> {
        &self.env_vars
    }

    pub fn get_command(&self) -> &str {
        &self.command
    }

    pub fn get_working_dir(&self) -> &PathBuf {
        &self.working_dir
    }
}

impl ProcessHandle {
    pub fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_pid(&self) -> Option<u32> {
        self.pid
    }
}

impl Drop for DevProcess {
    fn drop(&mut self) {
        if let Some(ref mut handle) = self.current_handle {
            // Try to kill the process if it's still running
            let _ = handle.child.start_kill();
        }
    }
}

// Additional utility functions for process management

pub async fn write_pid_file(path: &PathBuf, pid: u32) -> NebulaResult<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    
    tokio::fs::write(path, pid.to_string()).await
        .map_err(|e| NebulaError::config(format!("Failed to write PID file: {}", e)))?;
    
    Ok(())
}

pub async fn read_pid_file(path: &PathBuf) -> NebulaResult<u32> {
    let content = tokio::fs::read_to_string(path).await
        .map_err(|e| NebulaError::file_not_found(format!("Failed to read PID file: {}", e)))?;
    
    content.trim().parse()
        .map_err(|e| NebulaError::config(format!("Invalid PID file format: {}", e)))
}

pub fn is_process_running_by_pid(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        
        match kill(Pid::from_raw(pid as i32), None) {
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

// Add shell-words dependency to Cargo.toml:
// shell-words = "1.1"
