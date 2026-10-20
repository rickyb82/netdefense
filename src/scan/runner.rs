//! Subprocess execution with a hard timeout (shared shape with the kali-mcp
//! engine). stdin is closed; the child is killed if the timeout elapses.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

pub struct Output {
    pub stdout: String,
    pub stderr: String,
    /// Process exit code; reserved for callers that inspect non-zero exits.
    #[allow(dead_code)]
    pub code: Option<i32>,
    pub timed_out: bool,
    pub not_found: bool,
}

pub async fn run(bin: &str, args: &[String], timeout_secs: u64) -> Output {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let not_found = e.kind() == std::io::ErrorKind::NotFound;
            return Output {
                stdout: String::new(),
                stderr: format!("failed to spawn `{bin}`: {e}"),
                code: None,
                timed_out: false,
                not_found,
            };
        }
    };

    match timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await {
        Ok(Ok(o)) => Output {
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            code: o.status.code(),
            timed_out: false,
            not_found: false,
        },
        Ok(Err(e)) => Output {
            stdout: String::new(),
            stderr: format!("io error running `{bin}`: {e}"),
            code: None,
            timed_out: false,
            not_found: false,
        },
        Err(_) => Output {
            stdout: String::new(),
            stderr: format!("`{bin}` timed out after {timeout_secs}s and was killed"),
            code: None,
            timed_out: true,
            not_found: false,
        },
    }
}
