//! Management panel tests against the fake backend.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use runman_agent::backend::Instances;
use runman_agent::config::{Config, Store};
use runman_agent::fake::Fake;
use runman_agent::local_wg::LocalWg;
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

/// Panel in platform mode (a token is set).
async fn start() -> Panel {
    start_with_token("old-token-0123456789").await
}

async fn start_with_token(token: &str) -> Panel {
    let rfw = mock_rfw().await;
    let cfg = Config {
        web_password_hash: bcrypt::hash(PASSWORD, 4).unwrap(),
        token: token.into(),
        rfw_addr: rfw.to_string(),
        data_dir: std::env::temp_dir().join(format!("runman-web-data-{}", uuid::Uuid::new_v4())),
        ..Config::default()
    };
    let store = Store::in_memory(cfg);
    let fake = Fake::new();
    let agent = Agent::new(store.clone(), fake.services(), Timing::default());
    let local_wg = std::sync::Arc::new(
        LocalWg::load(
            &std::env::temp_dir().join(format!("runman-web-test-{}", uuid::Uuid::new_v4())),
        )
        .unwrap(),
    );
    let web = Web::new(agent, fake.services(), None, local_wg);
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

    // Tokens come from the platform: the panel never makes one up.
    let r = c
        .post(format!("{}/api/settings/token", p.base))
        .header("X-Runman", "1")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error());
    assert_eq!(p.store.get().token, "old-token-0123456789");

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

async fn post(c: &reqwest::Client, url: String, body: Value) -> reqwest::Response {
    c.post(url)
        .header("X-Runman", "1")
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn platform_mode_keeps_lifecycle_on_the_platform() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let o: Value = c
        .get(format!("{}/api/overview", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(o["mode"], "platform");
    let r = post(
        &c,
        format!("{}/api/instances", p.base),
        json!({"os_image": "debian", "cpu": 1, "ram_mb": 256, "disk_gb": 1}),
    )
    .await;
    assert_eq!(r.status(), 409);
    let r = c
        .delete(format!("{}/api/instances/{VM}", p.base))
        .header("X-Runman", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let r = post(
        &c,
        format!("{}/api/instances/{VM}/forwards", p.base),
        json!({"proto": "tcp", "guest_port": 80}),
    )
    .await;
    assert_eq!(r.status(), 409);
    assert_eq!(p.fake.instances.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn standalone_mode_manages_the_node() {
    let p = start_with_token("").await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let o: Value = c
        .get(format!("{}/api/overview", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(o["mode"], "standalone");

    // Create with a generated password and an automatic SSH forward.
    let r: Value = post(
        &c,
        format!("{}/api/instances", p.base),
        json!({"os_image": "alpine", "cpu": 2, "ram_mb": 1024, "disk_gb": 10, "bandwidth_mbps": 100}),
    )
    .await
    .json()
    .await
    .unwrap();
    let id = r["id"].as_str().unwrap().to_owned();
    assert_eq!(r["root_password"].as_str().unwrap().len(), 16);
    assert!(r["ssh_port"].as_u64().is_some());
    let invalid = post(
        &c,
        format!("{}/api/instances", p.base),
        json!({"os_image": "alpine", "cpu": 0, "ram_mb": 1, "disk_gb": 1}),
    )
    .await;
    assert_eq!(invalid.status(), 400);

    // Port forwards: automatic host port, then removal.
    let r: Value = post(
        &c,
        format!("{}/api/instances/{id}/forwards", p.base),
        json!({"proto": "udp", "guest_port": 51820}),
    )
    .await
    .json()
    .await
    .unwrap();
    let port = r["host_port"].as_u64().unwrap();
    assert!(
        p.fake
            .rules
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.host_port as u64 == port && f.guest_port == 51820)
    );
    let r = c
        .delete(format!("{}/api/instances/{id}/forwards/udp/{port}", p.base))
        .header("X-Runman", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Reinstall keeps the plan, changes the image.
    let r: Value = post(
        &c,
        format!("{}/api/instances/{id}/reinstall", p.base),
        json!({"os_image": "debian"}),
    )
    .await
    .json()
    .await
    .unwrap();
    assert!(r["root_password"].is_string());
    {
        let instances = p.fake.instances.lock().unwrap();
        let inst = instances
            .values()
            .find(|i| i.spec.vm_id.as_str() == id)
            .unwrap();
        assert_eq!(
            (inst.spec.os_image.as_str(), inst.spec.cpu, inst.spec.ram_mb),
            ("debian", 2, 1024)
        );
    }

    // Dedicated IP from a wg-quick config, applied through WgBindings.
    let conf = format!(
        "[Interface]\nPrivateKey = {k}\nAddress = 203.0.113.9/32\n[Peer]\nPublicKey = {k}\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n",
        k = format!("{}=", "A".repeat(43))
    );
    let r = post(
        &c,
        format!("{}/api/wg", p.base),
        json!({"vm_id": id, "config": conf}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(p.fake.wg.lock().unwrap().len(), 1);
    let listed: Value = c
        .get(format!("{}/api/wg", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed.to_string().contains("203.0.113.9"));
    assert!(
        !listed.to_string().contains("AAAA"),
        "keys must not be returned"
    );

    // Deleting the instance also drops its forwards and dedicated IPs.
    let r = c
        .delete(format!("{}/api/instances/{id}", p.base))
        .header("X-Runman", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(p.fake.wg.lock().unwrap().is_empty());
    assert!(
        p.fake
            .rules
            .lock()
            .unwrap()
            .iter()
            .all(|f| f.vm_id.as_str() != id)
    );

    // Joining the platform with local instances needs an explicit confirm.
    let r = post(
        &c,
        format!("{}/api/settings/token", p.base),
        json!({"token": "platform-token-0123456789"}),
    )
    .await;
    assert_eq!(r.status(), 409, "the fixture instance still exists locally");
    assert_eq!(p.store.get().token, "");
    let r = post(
        &c,
        format!("{}/api/settings/token", p.base),
        json!({"token": "platform-token-0123456789", "confirm": true}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(p.store.get().token, "platform-token-0123456789");
    let r = post(
        &c,
        format!("{}/api/settings/token", p.base),
        json!({"token": ""}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        p.store.get().token,
        "",
        "clearing returns to standalone mode"
    );
}

#[tokio::test]
async fn image_management_needs_a_capable_backend() {
    let p = start_with_token("").await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let r = c
        .get(format!("{}/api/images", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 501);
    let r = post(
        &c,
        format!("{}/api/images/builds", p.base),
        json!({"image_id": "web", "name": "Web", "base": "debian", "script": "true"}),
    )
    .await;
    assert_eq!(r.status(), 501);
}

#[tokio::test]
async fn traffic_schedule_settings() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    let put = |body: Value| {
        c.put(format!("{}/api/settings", p.base))
            .header("X-Runman", "1")
            .json(&body)
            .send()
    };
    let r = put(json!({"traffic_reset_day": 15, "traffic_timezone": "+08:00"}))
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let cfg = p.store.get();
    assert_eq!(
        (cfg.traffic_reset_day, cfg.traffic_timezone.as_str()),
        (15, "+08:00")
    );

    for bad in [
        json!({"traffic_reset_day": 29}),
        json!({"traffic_timezone": "Asia/Shanghai"}),
    ] {
        assert_eq!(put(bad).await.unwrap().status(), 400);
    }
    assert_eq!(
        p.store.get().traffic_reset_day,
        15,
        "rejected values are not stored"
    );

    let s: Value = c
        .get(format!("{}/api/settings", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s["traffic"]["reset_day"], 15);
    assert_eq!(s["traffic"]["timezone"], "+08:00");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let next = s["traffic"]["next_reset"].as_u64().unwrap();
    assert!(next > now && next - now <= 31 * 86_400);
    // Midnight in UTC+8 is 16:00 UTC.
    assert_eq!(next % 86_400, 16 * 3600);

    let r = put(json!({"traffic_reset_mode": "creation"}))
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        p.store.get().traffic_reset_mode,
        runman_agent::traffic::ResetMode::Creation
    );
    let r = put(json!({"traffic_reset_mode": "weekly"})).await.unwrap();
    assert!(r.status().is_client_error());
    assert_eq!(
        p.store.get().traffic_reset_mode,
        runman_agent::traffic::ResetMode::Creation
    );
}

#[tokio::test]
async fn bandwidth_correction() {
    let p = start().await;
    let c = client();
    login(&p, &c, PASSWORD).await;
    // Nothing measured yet: the owner's value is reported as is.
    let r = c
        .put(format!("{}/api/settings", p.base))
        .header("X-Runman", "1")
        .json(&json!({"bandwidth_mbps": 5000}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let s: Value = c
        .get(format!("{}/api/settings", p.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s["bandwidth"]["configured"], 5000);
    assert_eq!(s["bandwidth"]["reported"], 5000);
    assert!(s["bandwidth"]["speedtest"]["measured"].is_null());
}
