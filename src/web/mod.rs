//! Local management panel (`web_listen`, default `0.0.0.0:8792`).
//!
//! - Session login (bcrypt password from the config), HttpOnly +
//!   SameSite=Strict cookie, failed logins rate-limited per client address.
//! - Every state-changing request must also carry `X-Runman: 1`; WebSocket
//!   upgrades must come from the panel's own origin.
//! - The platform owns instance lifecycle, port forwards and WireGuard
//!   bindings: the panel shows them but only offers power actions, password
//!   resets and a console.
//! - `/rfw/api/*` is proxied to the rfw firewall's local API.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::backend::Services;
use crate::config;
use crate::model::{ConsoleSize, VmId, validate_password};
use crate::platform::Agent;
use crate::updater::{Outcome, Updater};

const COOKIE: &str = "rm_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const LOGIN_WINDOW: Duration = Duration::from_secs(600);
const LOGIN_MAX_FAILURES: usize = 5;
const PROXY_BODY_LIMIT: usize = 64 * 1024;

static UI: &str = include_str!("ui.html");

pub struct Web {
    agent: Arc<Agent>,
    services: Services,
    updater: Option<Arc<Updater>>,
    sessions: Mutex<HashMap<String, Instant>>,
    failures: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    http: Client<HttpConnector, Body>,
}

impl Web {
    pub fn new(agent: Arc<Agent>, services: Services, updater: Option<Arc<Updater>>) -> Arc<Self> {
        Arc::new(Self {
            agent,
            services,
            updater,
            sessions: Mutex::default(),
            failures: Mutex::default(),
            http: Client::builder(TokioExecutor::new()).build_http(),
        })
    }

    fn cfg(&self) -> &config::Store {
        self.agent.config()
    }

    pub async fn serve(
        self: Arc<Self>,
        listen: SocketAddr,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind {listen}"))?;
        info!("management panel on http://{listen}");
        self.serve_on(listener, shutdown).await
    }

    pub async fn serve_on(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let protected = Router::new()
            .route("/api/overview", get(overview))
            .route("/api/instances", get(instances))
            .route("/api/instances/{id}/power", post(power))
            .route("/api/instances/{id}/password", post(reset_password))
            .route("/api/instances/{id}/console-log", get(console_log))
            .route("/api/instances/{id}/tty", get(tty))
            .route("/api/settings", get(get_settings).put(put_settings))
            .route("/api/settings/token", post(rotate_token))
            .route("/api/settings/password", post(change_password))
            .route("/api/rfw/status", get(rfw_status))
            .route("/api/update", post(update_now))
            .route("/rfw/api/{*rest}", any(rfw_proxy))
            .route("/api/logout", post(logout))
            .route_layer(middleware::from_fn_with_state(
                self.clone(),
                require_session,
            ));
        let app = Router::new()
            .route("/", get(|| async { Html(UI) }))
            .route("/api/login", post(login))
            .merge(protected)
            .layer(middleware::from_fn(security_headers))
            .with_state(self.clone());
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await?;
        Ok(())
    }

    fn session_valid(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, exp| *exp > Instant::now());
        match sessions.get_mut(token) {
            Some(exp) => {
                *exp = Instant::now() + SESSION_TTL;
                true
            }
            None => false,
        }
    }
}

// ── errors ──────────────────────────────────────────────────────────────────

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}

type ApiResult<T> = Result<T, ApiError>;

// ── middleware ──────────────────────────────────────────────────────────────

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            v.split(';').find_map(|kv| {
                kv.trim()
                    .strip_prefix(&format!("{COOKIE}="))
                    .map(str::to_owned)
            })
        })
}

/// Same-origin check for WebSocket upgrades (browsers cannot add custom
/// headers to them, so the X-Runman check does not apply).
fn same_origin(headers: &HeaderMap) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    match (host, origin) {
        (Some(host), Some(origin)) => {
            origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
                == Some(host)
        }
        _ => false,
    }
}

async fn require_session(State(web): State<Arc<Web>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if !cookie_token(headers).is_some_and(|t| web.session_valid(&t)) {
        return err(StatusCode::UNAUTHORIZED, "not logged in").into_response();
    }
    let is_ws = headers
        .get(header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if is_ws {
        if !same_origin(headers) {
            return err(StatusCode::FORBIDDEN, "cross-origin websocket").into_response();
        }
    } else if req.method() != Method::GET
        && headers.get("x-runman").and_then(|v| v.to_str().ok()) != Some("1")
    {
        return err(StatusCode::FORBIDDEN, "missing X-Runman header").into_response();
    }
    next.run(req).await
}

// ── auth ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(
    State(web): State<Arc<Web>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> ApiResult<Response> {
    let ip = peer.ip();
    {
        let mut failures = web.failures.lock().unwrap();
        let list = failures.entry(ip).or_default();
        list.retain(|t| t.elapsed() < LOGIN_WINDOW);
        if list.len() >= LOGIN_MAX_FAILURES {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed logins, try again later",
            ));
        }
    }
    let cfg = web.cfg().get();
    if cfg.web_password_hash.is_empty() {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "panel password not set: run `runman-agent set-password`",
        ));
    }
    let hash = cfg.web_password_hash.clone();
    let password = req.password.clone();
    let ok_password =
        tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
            .await
            .unwrap_or(false);
    if !(ok_password && req.username == cfg.web_user) {
        web.failures
            .lock()
            .unwrap()
            .entry(ip)
            .or_default()
            .push(Instant::now());
        warn!("panel: failed login for {:?} from {ip}", req.username);
        return Err(err(StatusCode::UNAUTHORIZED, "wrong username or password"));
    }
    web.failures.lock().unwrap().remove(&ip);
    let token = random_token(48);
    web.sessions
        .lock()
        .unwrap()
        .insert(token.clone(), Instant::now() + SESSION_TTL);
    info!("panel: {} logged in from {ip}", req.username);
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

async fn logout(State(web): State<Arc<Web>>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_token(&headers) {
        web.sessions.lock().unwrap().remove(&t);
    }
    let cookie = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
}

pub fn random_token(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

// ── read-only views ─────────────────────────────────────────────────────────

async fn overview(State(web): State<Arc<Web>>) -> ApiResult<Json<Value>> {
    let cfg = web.cfg().get();
    let status = web.agent.status();
    let entry = web.agent.entry.read().unwrap().clone();
    let host = web.services.host.snapshot().await.ok();
    let images = web.services.instances.images().await.unwrap_or_default();
    let last_connected = status
        .last_connected
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    Ok(Json(json!({
        "version": crate::updater::version(),
        "update": web.updater.as_ref().map(|u| u.status()),
        "platform": {
            "url": cfg.platform_url,
            "connected": status.connected,
            "last_error": status.last_error,
            "last_connected": last_connected,
            "token_set": !cfg.token.is_empty(),
        },
        "entry": { "ipv4": entry.ipv4, "ipv6": entry.ipv6, "host": cfg.host },
        "host": host,
        "images": images.iter().map(|i| json!({ "id": i.id, "name": i.name })).collect::<Vec<_>>(),
    })))
}

async fn instances(State(web): State<Arc<Web>>) -> ApiResult<Json<Value>> {
    let details = web.services.instances.details().await?;
    let forwards = web
        .services
        .port_forwards
        .list(None)
        .await
        .unwrap_or_default();
    let list: Vec<Value> = details
        .into_iter()
        .map(|d| {
            let fw: Vec<_> = forwards
                .iter()
                .filter(|f| f.vm_id.as_str() == d.id)
                .collect();
            let mut v = serde_json::to_value(&d).unwrap_or_default();
            v["forwards"] = serde_json::to_value(fw).unwrap_or_default();
            v
        })
        .collect();
    Ok(Json(Value::Array(list)))
}

fn vm(id: &str) -> ApiResult<VmId> {
    VmId::parse(id).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{e:#}")))
}

#[derive(Deserialize)]
struct PowerReq {
    action: String,
}

async fn power(
    State(web): State<Arc<Web>>,
    Path(id): Path<String>,
    Json(req): Json<PowerReq>,
) -> ApiResult<Json<Value>> {
    let id = vm(&id)?;
    let inst = &web.services.instances;
    match req.action.as_str() {
        "start" => inst.start(&id).await?,
        "stop" => inst.stop(&id, false).await?,
        "force_stop" => inst.stop(&id, true).await?,
        "restart" => inst.restart(&id).await?,
        other => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!("unknown action {other:?}"),
            ));
        }
    }
    info!("panel: {} {id}", req.action);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PasswordReq {
    password: String,
}

async fn reset_password(
    State(web): State<Arc<Web>>,
    Path(id): Path<String>,
    Json(req): Json<PasswordReq>,
) -> ApiResult<Json<Value>> {
    let id = vm(&id)?;
    validate_password(&req.password)?;
    web.services
        .instances
        .reset_password(&id, &req.password)
        .await?;
    info!("panel: reset root password of {id}");
    Ok(Json(json!({ "ok": true })))
}

async fn console_log(State(web): State<Arc<Web>>, Path(id): Path<String>) -> ApiResult<Response> {
    let id = vm(&id)?;
    let text = web.services.instances.console_log(&id, 64 * 1024).await?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
}

#[derive(Deserialize)]
struct TtyQuery {
    cols: Option<u32>,
    rows: Option<u32>,
}

async fn tty(
    State(web): State<Arc<Web>>,
    Path(id): Path<String>,
    Query(q): Query<TtyQuery>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let id = vm(&id)?;
    let size = ConsoleSize::new(q.cols.unwrap_or(80), q.rows.unwrap_or(24));
    let io = web.services.instances.open_console(&id, size).await?;
    info!("panel: console opened for {id}");
    Ok(ws.on_upgrade(move |socket| bridge_tty(socket, io)))
}

/// Binary frames carry terminal bytes both ways; a text frame
/// `{"cols":..,"rows":..}` resizes.
async fn bridge_tty(mut socket: WebSocket, mut io: crate::backend::ConsoleIo) {
    loop {
        tokio::select! {
            out = io.output.recv() => match out {
                Some(data) => {
                    if socket.send(Message::Binary(data.into())).await.is_err() {
                        break;
                    }
                }
                None => {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    if io.input.send(data.to_vec()).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&text)
                        && let (Some(c), Some(r)) = (v["cols"].as_u64(), v["rows"].as_u64())
                        && let Some(size) = ConsoleSize::new(c as u32, r as u32)
                    {
                        let _ = io.resize.try_send(size);
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
        }
    }
    // Dropping `io` (and its input sender) closes the console session.
}

// ── settings ────────────────────────────────────────────────────────────────

async fn get_settings(State(web): State<Arc<Web>>) -> Json<Value> {
    let c = web.cfg().get();
    let token_hint = if c.token.len() > 8 {
        format!("…{}", &c.token[c.token.len() - 4..])
    } else {
        String::new()
    };
    Json(json!({
        "platform_url": c.platform_url,
        "host": c.host,
        "bandwidth_mbps": c.bandwidth_mbps,
        "virt_label": c.virt_label,
        "web_user": c.web_user,
        "token_hint": token_hint,
    }))
}

#[derive(Deserialize)]
struct SettingsReq {
    host: Option<String>,
    bandwidth_mbps: Option<u32>,
}

async fn put_settings(
    State(web): State<Arc<Web>>,
    Json(req): Json<SettingsReq>,
) -> ApiResult<Json<Value>> {
    if let Some(h) = &req.host
        && (h.len() > 253
            || h.chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '/'))
    {
        return Err(err(StatusCode::BAD_REQUEST, "invalid host"));
    }
    web.cfg().update(|c| {
        if let Some(h) = req.host {
            c.host = h;
        }
        if let Some(b) = req.bandwidth_mbps {
            c.bandwidth_mbps = b;
        }
    })?;
    info!("panel: settings updated");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct TokenReq {
    /// Custom token; empty or missing generates one.
    token: Option<String>,
}

async fn rotate_token(
    State(web): State<Arc<Web>>,
    Json(req): Json<TokenReq>,
) -> ApiResult<Json<Value>> {
    let token = req
        .token
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| random_token(48));
    web.cfg().update(|c| c.token = token.clone())?;
    web.agent.reconnect_now();
    info!("panel: integration token rotated");
    Ok(Json(json!({ "token": token })))
}

#[derive(Deserialize)]
struct ChangePasswordReq {
    old_password: String,
    new_password: String,
}

async fn change_password(
    State(web): State<Arc<Web>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordReq>,
) -> ApiResult<Json<Value>> {
    if req.new_password.len() < 8 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "new password must have at least 8 characters",
        ));
    }
    let hash = web.cfg().get().web_password_hash;
    let old = req.old_password.clone();
    let ok = tokio::task::spawn_blocking(move || bcrypt::verify(old, &hash).unwrap_or(false))
        .await
        .unwrap_or(false);
    if !ok {
        return Err(err(StatusCode::FORBIDDEN, "current password is wrong"));
    }
    let new_hash = hash_password(req.new_password).await?;
    web.cfg().update(|c| c.web_password_hash = new_hash)?;
    // Sign out every other session.
    let current = cookie_token(&headers);
    web.sessions
        .lock()
        .unwrap()
        .retain(|t, _| Some(t) == current.as_ref());
    info!("panel: password changed");
    Ok(Json(json!({ "ok": true })))
}

pub async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST))
        .await?
        .map_err(|e| anyhow!("hash password: {e}"))
}

async fn update_now(State(web): State<Arc<Web>>) -> ApiResult<Json<Value>> {
    let updater = web
        .updater
        .as_ref()
        .ok_or_else(|| err(StatusCode::NOT_IMPLEMENTED, "updates disabled"))?;
    match updater.update_now().await? {
        Outcome::UpToDate => Ok(Json(json!({ "updated": false }))),
        Outcome::Installed(sha) => {
            info!("panel: update {} installed, restarting", &sha[..12]);
            Ok(Json(json!({ "updated": true })))
        }
    }
}

// ── rfw ─────────────────────────────────────────────────────────────────────

async fn rfw_status(State(web): State<Arc<Web>>) -> Json<Value> {
    let service = tokio::process::Command::new("systemctl")
        .args(["is-active", "rfw"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let api = forward_rfw(&web, Method::GET, "status", None, Body::empty()).await;
    let api_status = match api {
        Ok(res) if res.status().is_success() => {
            let bytes = axum::body::to_bytes(Body::new(res.into_body()), PROXY_BODY_LIMIT)
                .await
                .unwrap_or_default();
            serde_json::from_slice::<Value>(&bytes).ok()
        }
        _ => None,
    };
    Json(json!({ "service": service, "api": api_status }))
}

async fn rfw_proxy(
    State(web): State<Arc<Web>>,
    Path(rest): Path<String>,
    req: Request,
) -> ApiResult<Response> {
    if rest.contains("..") || rest.starts_with('/') {
        return Err(err(StatusCode::BAD_REQUEST, "invalid path"));
    }
    let method = req.method().clone();
    let query = req.uri().query().map(str::to_owned);
    let body = axum::body::to_bytes(req.into_body(), PROXY_BODY_LIMIT)
        .await
        .map_err(|_| err(StatusCode::PAYLOAD_TOO_LARGE, "request too large"))?;
    let mut res = forward_rfw(
        &web,
        method.clone(),
        &rest,
        query.as_deref(),
        Body::from(body),
    )
    .await
    .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("rfw unreachable: {e:#}")))?;
    let status = res.status();
    let content_type = res.headers_mut().remove(header::CONTENT_TYPE);
    let bytes = axum::body::to_bytes(Body::new(res.into_body()), 4 * 1024 * 1024)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("rfw response: {e}")))?;
    if method != Method::GET {
        info!("panel: rfw {method} {rest} -> {status}");
    }
    let mut out = Response::builder().status(status);
    if let Some(ct) = content_type {
        out = out.header(header::CONTENT_TYPE, ct);
    }
    out.body(Body::from(bytes))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Send a request to rfw's local API (`/api/<rest>`).
async fn forward_rfw(
    web: &Web,
    method: Method,
    rest: &str,
    query: Option<&str>,
    body: Body,
) -> Result<Response<hyper::body::Incoming>> {
    let addr = web.cfg().get().rfw_addr;
    let mut uri = format!("http://{addr}/api/{rest}");
    if let Some(q) = query {
        uri.push('?');
        uri.push_str(q);
    }
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)?;
    let res = tokio::time::timeout(Duration::from_secs(10), web.http.request(request))
        .await
        .map_err(|_| anyhow!("timeout"))??;
    Ok(res)
}
