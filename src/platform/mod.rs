//! Platform session: one long-lived `AgentGateway.Connect` stream.
//!
//! Behavioural contract (kept identical to the Go agent):
//! - metadata `authorization: Bearer <token>`; TLS for `https://` endpoints;
//! - heartbeat right after connecting, then every 15 s;
//! - the platform pings every 15 s; no ping for 60 s means the stream is dead;
//! - every command except `Ping`, console frames and `WgSyncResponse` gets
//!   exactly one `CommandResult` (`CmdGetPortForwards` answers with
//!   `PortForwardList` instead);
//! - WireGuard bindings are pulled with `WgSyncRequest` every 20 s;
//! - reconnect with exponential backoff 5 s .. 5 min, reset after a session
//!   that actually connected.

mod commands;
mod console;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::{ClientTlsConfig, Endpoint};
use tracing::{debug, info, warn};

use crate::backend::Services;
use crate::config;
use crate::proto::agent_envelope::Payload as Up;
use crate::proto::agent_gateway_client::AgentGatewayClient;
use crate::proto::platform_envelope::Payload as Down;
use crate::proto::{self, AgentEnvelope, PlatformEnvelope};

pub use commands::CommandRunner;

#[derive(Debug, Clone)]
pub struct Timing {
    pub heartbeat: Duration,
    pub ping_timeout: Duration,
    pub wg_sync: Duration,
    pub wg_sync_timeout: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    pub connect_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(15),
            ping_timeout: Duration::from_secs(60),
            wg_sync: Duration::from_secs(20),
            wg_sync_timeout: Duration::from_secs(10),
            backoff_base: Duration::from_secs(5),
            backoff_max: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(15),
        }
    }
}

/// Sender for the currently open stream, if any.
///
/// Command results are sent through the link that is current when the command
/// finishes, so a result produced after a reconnect still reaches the platform.
#[derive(Clone, Default)]
pub struct Link(Arc<Mutex<Option<mpsc::Sender<AgentEnvelope>>>>);

impl Link {
    fn set(&self, tx: mpsc::Sender<AgentEnvelope>) {
        *self.0.lock().unwrap() = Some(tx);
    }

    fn clear_if(&self, tx: &mpsc::Sender<AgentEnvelope>) {
        let mut cur = self.0.lock().unwrap();
        if cur.as_ref().is_some_and(|c| c.same_channel(tx)) {
            *cur = None;
        }
    }

    /// Returns false when there is no connection or it closed meanwhile.
    pub async fn send(&self, payload: Up) -> bool {
        let tx = self.0.lock().unwrap().clone();
        match tx {
            Some(tx) => tx.send(envelope(payload)).await.is_ok(),
            None => false,
        }
    }
}

fn envelope(payload: Up) -> AgentEnvelope {
    AgentEnvelope {
        message_id: uuid::Uuid::new_v4().to_string(),
        payload: Some(payload),
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConnStatus {
    pub connected: bool,
    pub last_error: String,
    pub last_connected: Option<SystemTime>,
}

/// Public addresses advertised in heartbeats.
#[derive(Debug, Clone, Default)]
pub struct EntryAddrs {
    pub ipv4: String,
    pub ipv6: String,
}

pub struct Agent {
    cfg: Arc<config::Store>,
    services: Services,
    timing: Timing,
    link: Link,
    commands: Arc<CommandRunner>,
    status: RwLock<ConnStatus>,
    pub entry: RwLock<EntryAddrs>,
    /// Wakes the session loop to reconnect at once (e.g. new token).
    reconnect: tokio::sync::Notify,
}

impl Agent {
    pub fn new(cfg: Arc<config::Store>, services: Services, timing: Timing) -> Arc<Self> {
        let link = Link::default();
        Arc::new(Self {
            commands: CommandRunner::new(services.clone(), link.clone()),
            cfg,
            services,
            timing,
            link,
            status: RwLock::default(),
            entry: RwLock::default(),
            reconnect: tokio::sync::Notify::new(),
        })
    }

    pub fn config(&self) -> &Arc<config::Store> {
        &self.cfg
    }

    /// Drop the current platform session and connect again right away.
    pub fn reconnect_now(&self) {
        self.reconnect.notify_one();
    }

    /// Detect the public IPv4/IPv6 reported as entry addresses, every 5 min.
    pub async fn entry_loop(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            for (flag, url) in [
                ("-4", "https://api-ipv4.ip.sb/ip"),
                ("-6", "https://api-ipv6.ip.sb/ip"),
            ] {
                let out = tokio::process::Command::new("curl")
                    .args([flag, "-fsS", "--max-time", "10", url])
                    .output()
                    .await;
                let ip = out
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_owned())
                    .filter(|s| s.parse::<std::net::IpAddr>().is_ok());
                if let Some(ip) = ip {
                    let mut entry = self.entry.write().unwrap();
                    let slot = if flag == "-4" {
                        &mut entry.ipv4
                    } else {
                        &mut entry.ipv6
                    };
                    if *slot != ip {
                        info!(
                            "public {} address: {ip}",
                            if flag == "-4" { "IPv4" } else { "IPv6" }
                        );
                        *slot = ip;
                    }
                }
            }
            if sleep_or_cancel(Duration::from_secs(300), &shutdown).await {
                return;
            }
        }
    }

    pub fn status(&self) -> ConnStatus {
        self.status.read().unwrap().clone()
    }

    fn set_status(&self, connected: bool, err: String) {
        let mut s = self.status.write().unwrap();
        s.connected = connected;
        s.last_error = err;
        if connected {
            s.last_connected = Some(SystemTime::now());
        }
    }

    /// Run until `shutdown` is cancelled.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        let mut delay = self.timing.backoff_base;
        while !shutdown.is_cancelled() {
            let cfg = self.cfg.get();
            if cfg.token.is_empty() {
                self.set_status(false, "no token configured".into());
                if sleep_or_cancel(Duration::from_secs(10), &shutdown).await {
                    return;
                }
                continue;
            }

            let mut connected = false;
            let result = self.session(&cfg, &shutdown, &mut connected).await;
            if shutdown.is_cancelled() {
                return;
            }
            let msg = match &result {
                Ok(()) => "stream closed by platform".to_owned(),
                Err(e) => format!("{e:#}"),
            };
            if connected {
                delay = self.timing.backoff_base;
            }
            warn!("platform session ended: {msg}; reconnecting in {delay:?}");
            self.set_status(false, msg);
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
                _ = self.reconnect.notified() => delay = self.timing.backoff_base,
            }
            if !connected {
                delay = (delay * 2).min(self.timing.backoff_max);
            }
        }
    }

    async fn session(
        self: &Arc<Self>,
        cfg: &config::Config,
        shutdown: &CancellationToken,
        connected: &mut bool,
    ) -> Result<()> {
        let mut endpoint = Endpoint::from_shared(cfg.platform_url.clone())
            .context("invalid platform_url")?
            .connect_timeout(self.timing.connect_timeout)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true);
        if cfg.platform_url.starts_with("https://") {
            endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
        }
        let channel = endpoint.connect().await.context("connect platform")?;
        let mut client = AgentGatewayClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentEnvelope>(256);
        let mut request = tonic::Request::new(ReceiverStream::new(rx));
        let auth = format!("Bearer {}", cfg.token)
            .parse()
            .map_err(|_| anyhow!("token is not a valid header value"))?;
        request.metadata_mut().insert("authorization", auth);
        let mut inbound = client
            .connect(request)
            .await
            .context("open stream")?
            .into_inner();

        debug!("stream opened to {}", cfg.platform_url);
        self.link.set(tx.clone());

        let conn = shutdown.child_token();
        let last_ping = Arc::new(Mutex::new(Instant::now()));
        let wg_waiters: WgWaiters = Arc::default();
        let consoles = console::Consoles::new(self.services.instances.clone(), tx.clone());

        tokio::spawn(self.clone().heartbeat_loop(tx.clone(), conn.clone()));
        tokio::spawn(
            self.clone()
                .wg_sync_loop(tx.clone(), wg_waiters.clone(), conn.clone()),
        );

        let mut watchdog = tokio::time::interval(self.timing.ping_timeout / 6);
        let result = loop {
            tokio::select! {
                _ = conn.cancelled() => break Ok(()),
                _ = self.reconnect.notified() => break Err(anyhow!("reconnect requested")),
                _ = watchdog.tick() => {
                    if last_ping.lock().unwrap().elapsed() > self.timing.ping_timeout {
                        break Err(anyhow!("no ping from platform for {:?}", self.timing.ping_timeout));
                    }
                }
                msg = inbound.message() => match msg {
                    Ok(Some(env)) => {
                        // Only a message from the platform proves the session
                        // works (a proxy can answer the HTTP/2 request itself),
                        // so backoff resets and status flips here.
                        if !*connected {
                            *connected = true;
                            info!("connected to platform {}", cfg.platform_url);
                            self.set_status(true, String::new());
                        }
                        self.dispatch(env, &last_ping, &consoles, &wg_waiters).await
                    }
                    Ok(None) => break Ok(()),
                    Err(status) => break Err(anyhow!("stream error: {status}")),
                },
            }
        };
        conn.cancel();
        consoles.close_all();
        self.link.clear_if(&tx);
        result
    }

    async fn dispatch(
        &self,
        env: PlatformEnvelope,
        last_ping: &Mutex<Instant>,
        consoles: &console::Consoles,
        wg_waiters: &WgWaiters,
    ) {
        match env.payload {
            Some(Down::Ping(_)) => *last_ping.lock().unwrap() = Instant::now(),
            Some(Down::ConsoleOpen(c)) => consoles.open(c),
            Some(Down::ConsoleInput(c)) => consoles.input(&c.session_id, c.data),
            Some(Down::ConsoleResize(c)) => consoles.resize(&c.session_id, c.cols, c.rows),
            Some(Down::ConsoleClose(c)) => consoles.close(&c.session_id),
            Some(Down::WgSyncResponse(resp)) => {
                if let Some(waiter) = wg_waiters.lock().unwrap().remove(&resp.request_id) {
                    let _ = waiter.send(resp);
                }
            }
            payload => self.commands.submit(env.command_id, payload).await,
        }
    }

    async fn heartbeat_loop(
        self: Arc<Self>,
        tx: mpsc::Sender<AgentEnvelope>,
        conn: CancellationToken,
    ) {
        let mut tick = tokio::time::interval(self.timing.heartbeat);
        loop {
            tokio::select! {
                _ = conn.cancelled() => return,
                _ = tick.tick() => {}
            }
            match self.heartbeat().await {
                Ok(hb) => {
                    if tx.send(envelope(Up::Heartbeat(hb))).await.is_err() {
                        return;
                    }
                }
                Err(e) => warn!("collect heartbeat: {e:#}"),
            }
        }
    }

    async fn heartbeat(&self) -> Result<proto::Heartbeat> {
        let host = self.services.host.snapshot().await?;
        let vms = self.services.instances.list().await?;
        let os_images = self.services.instances.images().await?;
        let cfg = self.cfg.get();
        let entry = self.entry.read().unwrap().clone();
        Ok(proto::Heartbeat {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or_default(),
            cpu_pct: host.cpu_pct,
            ram_used_mb: host.ram_used_mb,
            disk_used_gb: host.disk_used_gb,
            net_in_bps: host.net_in_bps,
            net_out_bps: host.net_out_bps,
            vms,
            entry_host: if cfg.host.is_empty() {
                entry.ipv4
            } else {
                cfg.host
            },
            entry_ipv6: entry.ipv6,
            os_images,
            load1: host.load[0],
            load5: host.load[1],
            load15: host.load[2],
            uptime: host.uptime_secs,
            cpus: host.cpus,
            ram_total_mb: host.ram_total_mb,
            disk_total_gb: host.disk_total_gb,
            bandwidth_mbps: if host.bandwidth_mbps > 0 {
                host.bandwidth_mbps
            } else {
                cfg.bandwidth_mbps as i32
            },
            virt_type: cfg.virt_label,
        })
    }

    async fn wg_sync_loop(
        self: Arc<Self>,
        tx: mpsc::Sender<AgentEnvelope>,
        waiters: WgWaiters,
        conn: CancellationToken,
    ) {
        let mut tick = tokio::time::interval(self.timing.wg_sync);
        loop {
            tokio::select! {
                _ = conn.cancelled() => return,
                _ = tick.tick() => {}
            }
            let request_id = uuid::Uuid::new_v4().to_string();
            let (done_tx, done_rx) = oneshot::channel();
            waiters.lock().unwrap().insert(request_id.clone(), done_tx);
            let req = Up::WgSyncRequest(proto::WgSyncRequest {
                request_id: request_id.clone(),
            });
            if tx.send(envelope(req)).await.is_err() {
                return;
            }
            let resp = tokio::select! {
                _ = conn.cancelled() => return,
                r = tokio::time::timeout(self.timing.wg_sync_timeout, done_rx) => r,
            };
            waiters.lock().unwrap().remove(&request_id);
            match resp {
                Ok(Ok(resp)) => {
                    debug!("wg sync: {} desired bindings", resp.bindings.len());
                    if let Err(e) = self.services.wg.reconcile(resp.bindings).await {
                        warn!("wg reconcile: {e:#}");
                    }
                }
                _ => debug!("wg sync request {request_id} got no response"),
            }
        }
    }
}

type WgWaiters = Arc<Mutex<HashMap<String, oneshot::Sender<proto::WgSyncResponse>>>>;

/// Sleep; returns true if cancelled first.
async fn sleep_or_cancel(d: Duration, token: &CancellationToken) -> bool {
    tokio::select! {
        _ = token.cancelled() => true,
        _ = tokio::time::sleep(d) => false,
    }
}
