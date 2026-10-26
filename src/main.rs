use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use runman_agent::config::{self, BackendKind};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use runman_agent::backend::Services;
use runman_agent::fake::Fake;
#[cfg(target_os = "linux")]
use runman_agent::metrics::ProcMetrics;
use runman_agent::platform::{Agent, Timing};
#[cfg(target_os = "linux")]
use runman_agent::runtime::{Options, Runtime};
use runman_agent::updater::Updater;
use runman_agent::web::Web;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Parser)]
#[command(version = runman_agent::updater::version(), about = "Runman node agent")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = config::DEFAULT_PATH, global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent (default).
    Run,
    /// Set the management panel password, read from stdin (first line).
    SetPassword,
    /// Set the platform integration token and print it.
    SetToken {
        /// Use this token instead of generating a random one.
        #[arg(long)]
        token: Option<String>,
    },
    /// Probe the host and print suggested IPv6 settings for `[network]`.
    DetectIpv6,
}

fn main() -> Result<()> {
    // Helper modes fork and switch namespaces; they must run before any
    // thread (including the tokio runtime) exists.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|a| a == "__supervise") {
        let spec = args
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("usage: __supervise <spec>"))?;
        runman_agent::runtime::supervisor::main(std::path::Path::new(spec));
    }
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|a| a == "__exec") {
        runman_agent::runtime::exec::main(&args[2..]);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(agent_main())
}

async fn agent_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    let cli = Cli::parse();
    if let Some(Command::DetectIpv6) = cli.command {
        print!("{}", runman_agent::detect::detect_ipv6().await?.toml());
        return Ok(());
    }
    let store = config::Store::load(&cli.config)?;
    match cli.command {
        None | Some(Command::Run) => {}
        Some(Command::SetPassword) => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let password = line.trim_end_matches(['\r', '\n']).to_owned();
            anyhow::ensure!(
                password.len() >= 8,
                "password must have at least 8 characters"
            );
            let hash = runman_agent::web::hash_password(password).await?;
            store.update(|c| c.web_password_hash = hash)?;
            println!("panel password updated; restart the agent to sign out existing sessions");
            return Ok(());
        }
        Some(Command::DetectIpv6) => unreachable!("handled above"),
        Some(Command::SetToken { token }) => {
            let token = token.unwrap_or_else(|| runman_agent::web::random_token(48));
            store.update(|c| c.token = token.clone())?;
            println!("{token}");
            return Ok(());
        }
    }
    let cfg = store.get();
    info!(
        "runman-agent {} starting (backend {:?})",
        runman_agent::updater::version(),
        cfg.backend
    );

    let services = match cfg.backend {
        BackendKind::Fake => Fake::new().services(),
        #[cfg(not(target_os = "linux"))]
        BackendKind::Container => anyhow::bail!("the container backend requires Linux"),
        #[cfg(target_os = "linux")]
        BackendKind::Container => {
            let rt = Arc::new(Runtime::new(Options::from_config(&cfg))?);
            {
                let rt = rt.clone();
                tokio::spawn(async move {
                    if let Err(e) = rt.init().await {
                        tracing::error!("runtime init: {e:#}");
                    }
                    rt.images().sync().await;
                });
            }
            {
                let rt = rt.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                    loop {
                        tick.tick().await;
                        rt.sample_traffic().await;
                        rt.heal().await;
                    }
                });
            }
            Services {
                instances: rt.clone(),
                port_forwards: rt.clone(),
                wg: rt,
                host: Arc::new(ProcMetrics::new(cfg.data_dir.clone())),
            }
        }
    };
    let agent = Agent::new(store.clone(), services.clone(), Timing::default());

    let shutdown = CancellationToken::new();
    // Installing an update cancels `shutdown`, the process exits and
    // systemd starts the new binary.
    let updater = Updater::new(store, shutdown.clone())?;
    tokio::spawn(updater.clone().run(shutdown.clone()));
    tokio::spawn(agent.clone().entry_loop(shutdown.clone()));
    if !cfg.web_listen.is_empty() {
        let web = Web::new(agent.clone(), services, Some(updater.clone()));
        let listen = cfg.web_listen.parse()?;
        let stop = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = web.serve(listen, stop).await {
                tracing::error!("management panel: {e:#}");
            }
        });
    }
    let signal = shutdown.clone();
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        info!("shutting down");
        signal.cancel();
    });

    agent.run(shutdown).await;
    Ok(())
}
