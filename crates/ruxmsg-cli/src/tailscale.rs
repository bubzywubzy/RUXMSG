//! Tailscale CLI helpers.

use std::process::{Command as ProcessCommand, Stdio};

// =====================================================================
// TAILSCALE
// =====================================================================

pub(crate) fn tailscale_missing_message() -> String {
    "tailscale not found on PATH — install it from \
     https://tailscale.com/download and try again"
        .to_string()
}

pub(crate) fn tailscale_status() {
    match ProcessCommand::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);

            if text.contains("\"BackendState\":\"Running\"") {
                println!("tailscale: running");
            } else if text.contains("\"BackendState\":\"NeedsLogin\"") {
                println!("tailscale: installed, not logged in — run `tailscale up`");
            } else {
                println!("tailscale: installed, not running");
            }
        }

        Ok(output) => {
            println!(
                "tailscale status failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}

pub(crate) fn tailscale_up() {
    match ProcessCommand::new("tailscale")
        .arg("up")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) if status.success() => {
            println!("tailscale is up");
        }

        Ok(status) => {
            println!("`tailscale up` exited with {status}");
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}

pub(crate) fn tailscale_ip() {
    match ProcessCommand::new("tailscale").arg("ip").output() {
        Ok(output) if output.status.success() => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }

        Ok(output) => {
            println!(
                "tailscale ip failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}
