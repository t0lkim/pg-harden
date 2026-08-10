use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    pg_harden::run().await
}
