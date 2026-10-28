//! In-process mock of the platform side of `AgentGateway.Connect`.
#![allow(dead_code, clippy::large_enum_variant)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runman_agent::proto::agent_envelope::Payload as Up;
use runman_agent::proto::agent_gateway_server::{AgentGateway, AgentGatewayServer};
use runman_agent::proto::platform_envelope::Payload as Down;
use runman_agent::proto::{AgentEnvelope, PlatformEnvelope, WgBindDesired, WgSyncResponse};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status, Streaming};

pub const TOKEN: &str = "test-token-0123456789";

#[derive(Debug)]
pub enum Event {
    Connected { auth: String },
    Msg(AgentEnvelope),
    Disconnected,
}

type Downlink = (
    mpsc::Sender<Result<PlatformEnvelope, Status>>,
    CancellationToken,
);

#[derive(Clone)]
struct Gateway {
    events: mpsc::UnboundedSender<Event>,
    current: Arc<Mutex<Option<Downlink>>>,
    wg_bindings: Arc<Mutex<Vec<WgBindDesired>>>,
    wg_silent: Arc<AtomicBool>,
    ping_every: Option<Duration>,
}

#[tonic::async_trait]
impl AgentGateway for Gateway {
    type ConnectStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<PlatformEnvelope, Status>> + Send>,
    >;

    async fn connect(
        &self,
        request: Request<Streaming<AgentEnvelope>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let auth = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let _ = self.events.send(Event::Connected { auth: auth.clone() });
        if auth != format!("Bearer {TOKEN}") {
            return Err(Status::unauthenticated("bad token"));
        }

        let (tx, rx) = mpsc::channel(64);
        let closed = CancellationToken::new();
        *self.current.lock().unwrap() = Some((tx.clone(), closed.clone()));
        let mut upstream = request.into_inner();

        if let Some(every) = self.ping_every {
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(every).await;
                    let ping = PlatformEnvelope {
                        command_id: String::new(),
                        payload: Some(Down::Ping(Default::default())),
                    };
                    if tx.send(Ok(ping)).await.is_err() {
                        return;
                    }
                }
            });
        }

        let events = self.events.clone();
        let wg = self.wg_bindings.clone();
        let wg_silent = self.wg_silent.clone();
        tokio::spawn(async move {
            while let Ok(Some(msg)) = upstream.message().await {
                if let Some(Up::WgSyncRequest(req)) = &msg.payload
                    && !wg_silent.load(Ordering::SeqCst)
                {
                    let bindings = wg.lock().unwrap().clone();
                    let resp = Down::WgSyncResponse(WgSyncResponse {
                        request_id: req.request_id.clone(),
                        bindings,
                    });
                    let _ = tx
                        .send(Ok(PlatformEnvelope {
                            command_id: String::new(),
                            payload: Some(resp),
                        }))
                        .await;
                }
                let _ = events.send(Event::Msg(msg));
            }
            let _ = events.send(Event::Disconnected);
        });
        // Forward through a task that only holds the outgoing sender, so
        // cancelling `closed` ends the response stream (a server hang-up).
        let (out_tx, out_rx) = mpsc::channel(64);
        let mut rx = rx;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closed.cancelled() => return,
                    msg = rx.recv() => match msg {
                        Some(m) => if out_tx.send(m).await.is_err() { return },
                        None => return,
                    },
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }
}

pub struct Mock {
    pub url: String,
    events: mpsc::UnboundedReceiver<Event>,
    current: Arc<Mutex<Option<Downlink>>>,
    pub wg_bindings: Arc<Mutex<Vec<WgBindDesired>>>,
    /// When set, WgSyncRequests go unanswered.
    pub wg_silent: Arc<AtomicBool>,
}

impl Mock {
    pub async fn start(ping_every: Option<Duration>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (events_tx, events) = mpsc::unbounded_channel();
        let current = Arc::new(Mutex::new(None));
        let wg_bindings = Arc::new(Mutex::new(Vec::new()));
        let wg_silent = Arc::new(AtomicBool::new(false));
        let gw = Gateway {
            events: events_tx,
            current: current.clone(),
            wg_bindings: wg_bindings.clone(),
            wg_silent: wg_silent.clone(),
            ping_every,
        };
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AgentGatewayServer::new(gw))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        Self {
            url: format!("http://{addr}"),
            events,
            current,
            wg_bindings,
            wg_silent,
        }
    }

    pub async fn next(&mut self, within: Duration) -> Event {
        tokio::time::timeout(within, self.events.recv())
            .await
            .expect("timed out waiting for mock platform event")
            .expect("event channel closed")
    }

    /// Wait for an upstream message matching `pred`, skipping everything else.
    pub async fn expect<T>(
        &mut self,
        within: Duration,
        mut pred: impl FnMut(&Up) -> Option<T>,
    ) -> T {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Event::Msg(AgentEnvelope {
                payload: Some(p), ..
            }) = self.next(left).await
                && let Some(v) = pred(&p)
            {
                return v;
            }
        }
    }

    pub async fn expect_connected(&mut self, within: Duration) -> String {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Event::Connected { auth } = self.next(left).await {
                return auth;
            }
        }
    }

    pub async fn send(&self, command_id: &str, payload: Down) {
        self.send_raw(PlatformEnvelope {
            command_id: command_id.into(),
            payload: Some(payload),
        })
        .await;
    }

    pub async fn send_raw(&self, env: PlatformEnvelope) {
        let (tx, _) = self
            .current
            .lock()
            .unwrap()
            .clone()
            .expect("agent not connected");
        tx.send(Ok(env)).await.expect("send to agent");
    }

    /// Server-side close of the current stream.
    pub fn hang_up(&self) {
        if let Some((_, closed)) = self.current.lock().unwrap().take() {
            closed.cancel();
        }
    }
}
