//! Management panel tests against the fake backend.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use runman_agent::backend::Instances;
use runman_agent::config::{Config, Store};
use runman_agent::fake::Fake;
use runman_agent::model::{InstanceSpec, VmId};
use runman_agent::platform::{Agent, Timing};
use runman_agent::web::Web;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use tokio_util::sync::CancellationToken;

const VM: &str = "4f1c9a3e-8a5b-4c1d-9e2f-0a1b2c3d4e5f";
const PASSWORD: &str = "Panel-pass1";

struct Panel {
    base: String,
    addr: std::net::SocketAddr,
    fake: Arc<Fake>,
    store: Arc<Store>,
    _shutdown: tokio_util::sync::DropGuard,
}

async fn mock_rfw() -> std::net::SocketAddr {
    let app = Router::new()
        .route(
            "/api/status",
            get(|| async {
                axum::Json(json!({"iface": "eth0", "api_version": "0.1.0", "rule_count": 1}))
            }),
        )
        .route(
            "/api/rules",
            get(|| async { axum::Json(json!([{"id": 7, "priority": 100, "action": "block"}])) })
                .post(|body: String| async move { axum::Json(json!({"received": body})) }),
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

async fn start() -> Panel {
    let rfw = mock_rfw().await;
    let cfg = Config {
        web_password_hash: bcrypt::hash(PASSWORD, 4).unwrap(),
        token: "old-token-0123456789".into(),
        rfw_addr: rfw.to_string(),
        ..Config::default()
    };
    let store = Store::in_memory(cfg);
    let fake = Fake::new();
    let agent = Agent::new(store.clone(), fake.services(), Timing::default());
    let web = Web::new(agent, fake.services(), None);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    tokio::spawn(web.serve_on(l, shutdown.clone()));
    fake.create(&InstanceSpec {
        vm_id: VmId::parse(VM).unwrap(),
        cpu: 1,
        ram_mb: 256,
        disk_gb: 1,
        bandwidth_mbps: 0,
        os_image: "debian".into(),
        root_password: "x-pass-1".into(),
    })
    .await
    .unwrap();
    Panel {
        base: format!("http://{addr}"),
        addr,
        fake,
        store,
        _shutdown: shutdown.drop_guard(),
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap()
}

async fn login(p: &Panel, c: &reqwest::Client, password: &str) -> reqwest::StatusCode {
    c.post(format!("{}/api/login", p.base))
        .json(&json!({"username": "admin", "password": password}))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn requires_login_and_serves_ui() {
    let p = start().await;
    let c = client();
    let ui = c.get(&p.base).send().await.unwrap();
    assert_eq!(ui.status(), 200);
    assert_eq!(ui.headers()["x-frame-options"], "DENY");
    assert!(ui.text().await.unwrap().contains("Runman"));
    assert_eq!(
        c.get(format!("{}/api/overview", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        c.get(format!("{}/rfw/api/rules", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    assert_eq!(login(&p, &c, PASSWORD).await, 200);
    let o: Value = c
        .get(format!("{}/api/overview", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(o["version"], runman_agent::updater::version());
    assert_eq!(o["platform"]["connected"], false);

    let list: Value = c
        .get(format!("{}/api/instances", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list[0]["id"], VM);
    assert_eq!(list[0]["status"], "running");

    assert_eq!(
        c.post(format!("{}/api/logout", p.base))
            .header("X-Runman", "1")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        c.get(format!("{}/api/overview", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

#[tokio::test]
async fn failed_logins_are_rate_limited() {
    let p = start().await;
    let c = client();
    for _ in 0..5 {
        assert_eq!(login(&p, &c, "wrong-password").await, 401);
    }
    assert_eq!(
        login(&p, &c, PASSWORD).await,
        429,
        "locked even with the right password"
    );
}

#[tokio::test]
async fn mutations_need_the_csrf_header() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let url = format!("{}/api/instances/{VM}/power", p.base);
    let r = c
        .post(&url)
        .json(&json!({"action": "stop"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(p.fake.instances.lock().unwrap().values().all(|i| i.running));

    let r = c
        .post(&url)
        .header("X-Runman", "1")
        .json(&json!({"action": "stop"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        p.fake
            .instances
            .lock()
            .unwrap()
            .values()
            .all(|i| !i.running)
    );

    let r = c
        .post(&url)
        .header("X-Runman", "1")
        .json(&json!({"action": "explode"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = c
        .post(format!("{}/api/instances/not-a-uuid/power", p.base))
        .header("X-Runman", "1")
        .json(&json!({"action": "start"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    let r = c
        .post(format!("{}/api/instances/{VM}/password", p.base))
        .header("X-Runman", "1")
        .json(&json!({"password": "New-root-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        p.fake
            .instances
            .lock()
            .unwrap()
            .values()
            .all(|i| i.spec.root_password == "New-root-1")
    );
}

#[tokio::test]
async fn settings_token_and_password() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let other = client();
    login(&p, &other, PASSWORD).await;

    let s: Value = c
        .get(format!("{}/api/settings", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s["token_hint"], "…6789");
    assert!(
        s.get("token").is_none(),
        "the full token must not be exposed"
    );

    let r: Value = c
        .post(format!("{}/api/settings/token", p.base))
        .header("X-Runman", "1")
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = r["token"].as_str().unwrap();
    assert_eq!(token.len(), 48);
    assert_eq!(p.store.get().token, token);

    let r = c
        .put(format!("{}/api/settings", p.base))
        .header("X-Runman", "1")
        .json(&json!({"host": "node1.example.com", "bandwidth_mbps": 1000}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(p.store.get().host, "node1.example.com");
    assert_eq!(p.store.get().bandwidth_mbps, 1000);

    let change = |old: &str, new: &str| {
        c.post(format!("{}/api/settings/password", p.base))
            .header("X-Runman", "1")
            .json(&json!({"old_password": old, "new_password": new}))
            .send()
    };
    assert_eq!(
        change("wrong", "Another-pass2").await.unwrap().status(),
        403
    );
    assert_eq!(change(PASSWORD, "short").await.unwrap().status(), 400);
    assert_eq!(
        change(PASSWORD, "Another-pass2").await.unwrap().status(),
        200
    );
    // This session survives, the other one is signed out.
    assert_eq!(
        c.get(format!("{}/api/overview", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        other
            .get(format!("{}/api/overview", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(login(&p, &client(), "Another-pass2").await, 200);
}

#[tokio::test]
async fn proxies_rfw_api() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let st: Value = c
        .get(format!("{}/api/rfw/status", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st["api"]["iface"], "eth0");
    let rules: Value = c
        .get(format!("{}/rfw/api/rules", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rules[0]["id"], 7);
    let r: Value = c
        .post(format!("{}/rfw/api/rules", p.base))
        .header("X-Runman", "1")
        .json(&json!({"priority": 1}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["received"], r#"{"priority":1}"#);
    let r = c
        .post(format!("{}/rfw/api/rules", p.base))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "proxy mutations also need the CSRF header");
}

#[tokio::test]
async fn websocket_console() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let cookie = c
        .post(format!("{}/api/login", p.base))
        .json(&json!({"username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let url = format!("ws://{}/api/instances/{VM}/tty?cols=80&rows=24", p.addr);

    let mut req = url.clone().into_client_request().unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut()
        .insert("origin", "http://evil.example".parse().unwrap());
    let refused = tokio_tungstenite::connect_async(req).await;
    assert!(matches!(refused, Err(tungstenite::Error::Http(r)) if r.status() == 403));

    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("cookie", cookie.parse().unwrap());
    req.headers_mut()
        .insert("origin", format!("http://{}", p.addr).parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("same-origin websocket");
    ws.send(tungstenite::Message::Binary(b"echo me".to_vec().into()))
        .await
        .unwrap();
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg.into_data().as_ref(), b"echo me");
    ws.send(tungstenite::Message::Text(
        r#"{"cols":120,"rows":40}"#.into(),
    ))
    .await
    .unwrap();
    ws.close(None).await.unwrap();
}
