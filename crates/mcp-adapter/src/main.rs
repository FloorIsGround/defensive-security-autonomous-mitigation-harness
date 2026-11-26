use std::{fs, path::PathBuf, process::ExitCode, time::Duration};

use clap::Parser;
use mcp_adapter::{McpServer, Mode};
use tokio::io::{BufReader, stdin, stdout};

#[derive(Parser)]
#[command(version, about = "Restricted Investigation MCP server over stdio")]
struct Args {
    #[arg(long, default_value = "./control-data/investigate.sock")]
    investigate_sock: PathBuf,
    #[arg(long, value_enum, default_value = "read-only")]
    mode: Mode,
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_seconds: u64,
}

impl Args {
    fn take_token(&mut self) -> Result<String, &'static str> {
        let token = if let Some(token) = self.token.take() {
            token
        } else if let Some(path) = &self.token_file {
            fs::read_to_string(path).map_err(|_| "could not read capability token file")?
        } else {
            std::env::var("DEFSEC_CAPABILITY_TOKEN").map_err(|_| {
                "provide a capability token with --token, --token-file, or DEFSEC_CAPABILITY_TOKEN"
            })?
        };

        let token = token.trim();
        if token.is_empty() {
            return Err("capability token is empty");
        }
        Ok(token.to_owned())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = Args::parse();
    let token = match args.take_token() {
        Ok(token) => token,
        Err(message) => {
            eprintln!("defsecautmit-mcp: {message}");
            return ExitCode::FAILURE;
        }
    };

    let server = McpServer::new(
        args.mode,
        args.investigate_sock,
        token,
        Duration::from_secs(args.timeout_seconds),
    );
    if let Err(error) = server.serve(BufReader::new(stdin()), stdout()).await {
        eprintln!("defsecautmit-mcp: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
