
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::warn;
use tokio::time::{sleep, Duration};

/// 优雅地终止进程
/// 首先发送 SIGTERM 信号，等待指定时间后如果进程仍未退出，则发送 SIGKILL 强制终止
pub async fn graceful_kill_process(child: &mut tokio::process::Child, graceful_timeout_secs: u64) -> anyhow::Result<()> {
    if let Some(pid) = child.id() {
        let nix_pid = Pid::from_raw(pid as i32);
        
        // 1. 首先发送 SIGTERM 信号
        warn!("Sending SIGTERM to process {}", pid);
        if let Err(e) = signal::kill(nix_pid, Signal::SIGTERM) {
            warn!("Failed to send SIGTERM to process {}: {}", pid, e);
            // 如果发送 SIGTERM 失败，直接使用 SIGKILL
            let _ = child.kill().await;
            return Ok(());
        }
        
        // 2. 等待进程优雅退出
        let graceful_timeout = sleep(Duration::from_secs(graceful_timeout_secs));
        tokio::pin!(graceful_timeout);
        
        tokio::select! {
            // 进程在优雅时间内退出
            exit_result = child.wait() => {
                match exit_result {
                    Ok(status) => {
                        warn!("Process {} exited gracefully with status: {}", pid, status);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Error waiting for process {} to exit: {}", pid, e);
                    }
                }
            }
            // 优雅超时，强制终止
            _ = &mut graceful_timeout => {
                warn!("Process {} did not exit gracefully within {} seconds, sending SIGKILL", pid, graceful_timeout_secs);
                let _ = child.kill().await;
                let _ = child.wait().await; // 等待进程真正退出
            }
        }
    } else {
        warn!("Process has no PID, using direct kill");
        let _ = child.kill().await;
    }
    
    Ok(())
}