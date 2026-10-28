use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use runman_agent::config::{self, BackendKind};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use runman_agent::backend::Services;
use runman_agent::fake::Fake;
use runman_agent::local_wg::LocalWg;
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
    /// Set the token issued by the platform (restart the agent afterwards).
    SetToken {
        /// Token from the platform.
        #[arg(required_unless_present = "clear")]
        token: Option<String>,
        /// Remove the token: the agent stops talking to the platform and the
        /// panel manages the node on its own.
        #[arg(long, conflicts_with = "token")]
        clear: bool,
    },
    /// Probe the host and print suggested IPv6 settings for `[network]`.
    DetectIpv6,
    /// Measure the uplink bandwidth now and save it (restart the agent to
    /// report a result measured here).
    Speedtest,
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
        Some(Command::Speedtest) => {
            let speed = runman_agent::speedtest::SpeedTest::load(&store.get().data_dir);
            let m = speed.run().await?;
            println!(
                "download {} Mbps, upload {} Mbps -> {} Mbps",
                m.down_mbps,
                m.up_mbps,
                m.mbps()
            );
            return Ok(());
        }
        Some(Command::SetToken { token, clear }) => {
            let token = if clear {
                String::new()
            } else {
                token.unwrap_or_default()
            };
            store.update(|c| c.token = token.clone())?;
            println!(
                "{}",
                if clear {
                    "platform token cleared (standalone mode)"
                } else {
                    "platform token set"
                }
            );
            return Ok(());
        }
    }
    let cfg = store.get();
    info!(
        "runman-agent {} starting (backend {:?})",
        runman_agent::updater::version(),
        cfg.backend
    );

    let local_wg = Arc::new(LocalWg::load(&cfg.data_dir)?);
    let services = match cfg.backend {
        BackendKind::Fake => Fake::new().services(),
        #[cfg(not(target_os = "linux"))]
        BackendKind::Container => anyhow::bail!("the container backend requires Linux"),
        #[cfg(target_os = "linux")]
        BackendKind::Container => {
            let rt = Arc::new(Runtime::new(Options::from_config(&cfg))?.with_config(store.clone()));
            {
                let rt = rt.clone();
                let store_for_init = store.clone();
                let local_wg_for_init = local_wg.clone();
                tokio::spawn(async move {
                    if let Err(e) = rt.init().await {
                        tracing::error!("runtime init: {e:#}");
                    }
                    // Standalone: nobody else will hand out the bindings.
                    if store_for_init.get().token.is_empty()
                        && let Err(e) = local_wg_for_init.apply(rt.as_ref()).await
                    {
                        tracing::warn!("apply local dedicated IPs: {e:#}");
                    }
                    // Official images: at start, then every 6 hours.
                    loop {
                        rt.refresh_images().await;
                        tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
                    }
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
            {
                let rt = rt.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        rt.sample_history().await;
                    }
                });
            }
            Services {
                instances: rt.clone(),
                port_forwards: rt.clone(),
                wg: rt.clone(),
                host: Arc::new(ProcMetrics::new(cfg.data_dir.clone())),
                images: Some(Arc::new(runman_agent::runtime::build::ImageAdminHandle(
                    rt.clone(),
                ))),
                monitor: Some(Arc::new(runman_agent::runtime::monitor::MonitorHandle(rt))),
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
    if cfg.backend != BackendKind::Fake {
        let (speed, stop) = (agent.speed.clone(), shutdown.clone());
        tokio::spawn(async move { speed.schedule(stop).await });
    }
    if !cfg.web_listen.is_empty() {
        let web = Web::new(
            agent.clone(),
            services,
            Some(updater.clone()),
            local_wg.clone(),
        );
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
