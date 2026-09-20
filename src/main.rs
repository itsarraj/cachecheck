use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use cachecheck::audit::audit_headers;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "cachecheck",
    about = "Audits a live URL's HTTP caching headers for common misconfigurations"
)]
struct Cli {
    url: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let response = match reqwest::get(&cli.url).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cachecheck: requesting {}: {e}", cli.url);
            return ExitCode::FAILURE;
        }
    };

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let findings = audit_headers(&headers, now);

    if findings.is_empty() {
        println!("cachecheck: no caching issues found");
        ExitCode::SUCCESS
    } else {
        for f in &findings {
            println!("[{}] {}", f.rule, f.message);
        }
        eprintln!("\ncachecheck: {} issue(s) found", findings.len());
        ExitCode::FAILURE
    }
}
