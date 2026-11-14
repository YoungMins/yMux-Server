use std::process::ExitCode;
use std::sync::Arc;

use ymux_server::config::{data_dir_from_env, Config};
use ymux_server::push::WebPush;
use ymux_server::server::{start, AppState, VERSION};
use ymux_server::state::{self, Store};

const HELP: &str = "ymux-server: relay for yMux remote control

USAGE:
    ymux-server              run the server (default)
    ymux-server token        print the setup token
    ymux-server token --rotate   replace the setup token and print the new one
    ymux-server --version

ENVIRONMENT:
    YMUX_SERVER_PUBLIC_URL   required, https://... (http://localhost allowed for development)
    YMUX_SERVER_BIND         default 127.0.0.1:11020
    YMUX_SERVER_DATA_DIR     default ./data
    YMUX_SERVER_TRUST_PROXY  1 to take the client address from the LAST X-Forwarded-For hop
                             (the proxy must overwrite or append to that header itself)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        Some("token") => token(args.iter().any(|a| a == "--rotate")),
        Some("--version") | Some("-V") => {
            println!("ymux-server {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") | Some("help") => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown argument: {other}\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

/// Touches only the `setup-token` file (never `state.json`), so it can run
/// while the server does and cannot undo or lose anything the server writes.
fn token(rotate: bool) -> ExitCode {
    let dir = data_dir_from_env();
    let result = if rotate {
        state::rotate_token(&dir)
    } else {
        state::token_for_cli(&dir)
    };
    match result {
        Ok(t) => {
            println!("{t}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "error: cannot use the setup token in {}: {e}",
                dir.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn serve() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ymux_server=info".into()),
        )
        .init();
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (store, created) = match Store::open(&cfg.data_dir) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if created {
        // Never the token itself: deployment logs are kept and shipped.
        println!(
            "First run: a setup token was created. Show it with `ymux-server token` \
             (Docker: `docker compose exec <service> ymux-server token`)."
        );
    }
    let subject = if cfg.https {
        cfg.origin.clone()
    } else {
        "mailto:ymux-server@localhost".to_string()
    };
    let Some(push) = WebPush::new(
        &store.state.vapid_private,
        &store.state.vapid_public,
        subject,
    ) else {
        eprintln!("error: the VAPID key in the state file is invalid");
        return ExitCode::FAILURE;
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(cfg.bind).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: cannot bind {}: {e}", cfg.bind);
                return ExitCode::FAILURE;
            }
        };
        let origin = cfg.origin.clone();
        let state = AppState::new(cfg, store, Arc::new(push));
        let running = match start(state, listener) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        tracing::info!(addr = %running.addr, public = %origin, version = VERSION, "listening");
        let token = running.shutdown_token();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            token.cancel();
        });
        let wait = running.wait();
        tokio::pin!(wait);
        tokio::select! {
            _ = &mut wait => {}
            _ = async {
                let _ = tokio::signal::ctrl_c().await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            } => {}
        }
        ExitCode::SUCCESS
    })
}
