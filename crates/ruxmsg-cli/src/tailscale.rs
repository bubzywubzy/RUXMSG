//! Tailscale CLI helpers.

use std::process::{Command as ProcessCommand, Stdio};

use ruxmsg::display::sanitize_for_display;

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
            let text: String = String::from_utf8_lossy(&output.stdout)
                .chars()
                .filter(|c| !c.is_control())
                .collect();

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
                sanitize_for_display(&String::from_utf8_lossy(&output.stderr))
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
            print!(
                "{}",
                sanitize_for_display(&String::from_utf8_lossy(&output.stdout))
            );
        }

        Ok(output) => {
            println!(
                "tailscale ip failed: {}",
                sanitize_for_display(&String::from_utf8_lossy(&output.stderr))
            );
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}
