//! Protocol conformance tests against an in-process mock platform.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{Event, Mock, TOKEN};
use runman_agent::config::{Config, Store};
use runman_agent::fake::Fake;
use runman_agent::platform::{Agent, Timing};
use runman_agent::proto::agent_envelope::Payload as Up;
use runman_agent::proto::platform_envelope::Payload as Down;
use runman_agent::proto::{self, CommandResult, ConsoleEventType};
use tokio_util::sync::CancellationToken;

const VM: &str = "4f1c9a3e-8a5b-4c1d-9e2f-0a1b2c3d4e5f";
const WAIT: Duration = Duration::from_secs(5);

struct Harness {
    agent: Arc<Agent>,
    mock: Mock,
    fake: Arc<Fake>,
    shutdown: CancellationToken,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn start(ping_every: Option<Duration>, timing: Timing) -> Harness {
    start_opts(ping_every, timing, false).await
}

async fn start_opts(ping_every: Option<Duration>, timing: Timing, wg_silent: bool) -> Harness {
    let mock = Mock::start(ping_every).await;
    mock.wg_silent
        .store(wg_silent, std::sync::atomic::Ordering::SeqCst);
    let fake = Fake::new();
    let cfg = Config {
        platform_url: mock.url.clone(),
        token: TOKEN.into(),
        ..Config::default()
    };
    let agent = Agent::new(Store::in_memory(cfg), fake.services(), timing);
    let shutdown = CancellationToken::new();
    tokio::spawn(agent.clone().run(shutdown.clone()));
    Harness {
        agent,
        mock,
        fake,
        shutdown,
    }
}

fn fast() -> Timing {
    Timing {
        heartbeat: Duration::from_millis(200),
        ping_timeout: Duration::from_secs(30),
        wg_sync: Duration::from_millis(200),
        wg_sync_timeout: Duration::from_secs(1),
        backoff_base: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        connect_timeout: Duration::from_secs(2),
    }
}

async fn result_for(mock: &mut Mock, id: &str) -> CommandResult {
    mock.expect(WAIT, |p| match p {
        Up::CmdResult(r) if r.command_id == id => Some(r.clone()),
        _ => None,
    })
    .await
}

fn create(vm: &str) -> Down {
    Down::CreateVm(proto::CmdCreateVm {
        vm_id: vm.into(),
        cpu: 1,
        ram_mb: 256,
        disk_gb: 5,
        bandwidth_mbps: 100,
        os_image: "debian".into(),
        root_password: "Secret-pass1".into(),
    })
}

#[tokio::test]
async fn sends_bearer_token_and_immediate_heartbeat() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    assert_eq!(
        h.mock.expect_connected(WAIT).await,
        format!("Bearer {TOKEN}")
    );
    let hb = h
        .mock
        .expect(WAIT, |p| match p {
            Up::Heartbeat(hb) => Some(hb.clone()),
            _ => None,
        })
        .await;
    assert_eq!(hb.virt_type, "container");
    assert_eq!(hb.cpus, 2);
    assert!(hb.timestamp > 0);
    assert_eq!(
        hb.os_images
            .iter()
            .map(|i| i.id.as_str())
            .collect::<Vec<_>>(),
        ["debian", "alpine"]
    );
}

#[tokio::test]
async fn create_acks_reports_vm_and_adds_ssh_forward() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    h.mock.expect_connected(WAIT).await;
    h.mock.send("c1", create(VM)).await;
    let r = result_for(&mut h.mock, "c1").await;
    assert!(r.success, "{}", r.error);

    let hb = h
        .mock
        .expect(WAIT, |p| match p {
            Up::Heartbeat(hb) if !hb.vms.is_empty() => Some(hb.clone()),
            _ => None,
        })
        .await;
    assert_eq!(hb.vms[0].vm_id, VM);
    assert_eq!(hb.vms[0].status, proto::VmStatus::Running as i32);

    h.mock
        .send(
            "q1",
            Down::GetPortFwds(proto::CmdGetPortForwards { vm_id: VM.into() }),
        )
        .await;
    let list = h
        .mock
        .expect(WAIT, |p| match p {
            Up::PortFwdList(l) => Some(l.clone()),
            Up::CmdResult(r) if r.command_id == "q1" => {
                panic!("get_port_fwds answered with CommandResult")
            }
            _ => None,
        })
        .await;
    assert_eq!(list.command_id, "q1");
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].guest_port, 22);
    assert_eq!(list.entries[0].protocol, proto::Protocol::Tcp as i32);
}

#[tokio::test]
async fn rejects_invalid_input_with_error_result() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    h.mock.expect_connected(WAIT).await;

    h.mock.send("bad-id", create("../../etc")).await;
    let r = result_for(&mut h.mock, "bad-id").await;
    assert!(!r.success);
    assert!(r.error.contains("invalid vm_id"), "{}", r.error);

    let bad_port = Down::SetPortFwd(proto::CmdSetPortForward {
        vm_id: VM.into(),
        protocol: proto::Protocol::Tcp as i32,
        host_port: 70000,
        guest_port: 22,
        description: String::new(),
    });
    h.mock.send("bad-port", bad_port).await;
    assert!(!result_for(&mut h.mock, "bad-port").await.success);

    // A payload this agent does not understand must still be acknowledged.
    h.mock
        .send_raw(proto::PlatformEnvelope {
            command_id: "empty".into(),
            payload: None,
        })
        .await;
    let r = result_for(&mut h.mock, "empty").await;
    assert!(!r.success);

    h.mock
        .send(
            "stop-missing",
            Down::StopVm(proto::CmdStopVm {
                vm_id: VM.into(),
                force: true,
            }),
        )
        .await;
    let r = result_for(&mut h.mock, "stop-missing").await;
    assert!(!r.success);
    assert_eq!(h.fake.create_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replayed_command_is_not_executed_twice() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    h.mock.expect_connected(WAIT).await;
    h.mock.send("dup", create(VM)).await;
    assert!(result_for(&mut h.mock, "dup").await.success);
    h.mock.send("dup", create(VM)).await;
    assert!(result_for(&mut h.mock, "dup").await.success);
    assert_eq!(h.fake.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn result_finished_after_reconnect_reaches_new_stream() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    *h.fake.create_delay.lock().unwrap() = Duration::from_millis(800);
    h.mock.expect_connected(WAIT).await;
    h.mock.send("slow", create(VM)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.mock.hang_up();
    h.mock.expect_connected(WAIT).await;
    // Platform replays the in-flight command; it must not run again.
    h.mock.send("slow", create(VM)).await;
    assert!(result_for(&mut h.mock, "slow").await.success);
    assert_eq!(h.fake.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_pings_force_reconnect() {
    let timing = Timing {
        ping_timeout: Duration::from_millis(400),
        ..fast()
    };
    let mut h = start(None, timing).await;
    h.mock.expect_connected(WAIT).await;
    let mut saw_disconnect = false;
    loop {
        match h.mock.next(WAIT).await {
            Event::Disconnected => saw_disconnect = true,
            Event::Connected { .. } if saw_disconnect => break,
            _ => {}
        }
    }
}

#[tokio::test]
async fn silent_stream_is_not_reported_connected() {
    // No pings and no WG sync answers: the platform never says anything.
    let timing = Timing {
        ping_timeout: Duration::from_secs(30),
        ..fast()
    };
    let mut h = start_opts(None, timing, true).await;
    h.mock.expect_connected(WAIT).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!h.agent.status().connected);
}

#[tokio::test]
async fn first_platform_message_marks_connected() {
    let mut h = start(Some(Duration::from_millis(50)), fast()).await;
    h.mock.expect_connected(WAIT).await;
    for _ in 0..50 {
        if h.agent.status().connected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("agent never reported connected");
}

#[tokio::test]
async fn wrong_token_is_retried_with_backoff() {
    let mock = Mock::start(None).await;
    let fake = Fake::new();
    let cfg = Config {
        platform_url: mock.url.clone(),
        token: "wrong-token-0123456789".into(),
        ..Config::default()
    };
    let agent = Agent::new(Store::in_memory(cfg), fake.services(), fast());
    let shutdown = CancellationToken::new();
    tokio::spawn(agent.clone().run(shutdown.clone()));
    let mut mock = mock;
    mock.expect_connected(WAIT).await;
    mock.expect_connected(WAIT).await;
    let status = agent.status();
    assert!(!status.connected);
    assert!(
        status.last_error.contains("bad token"),
        "{}",
        status.last_error
    );
    shutdown.cancel();
}

#[tokio::test]
async fn wg_bindings_are_pulled_and_reconciled() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    h.mock
        .wg_bindings
        .lock()
        .unwrap()
        .push(proto::WgBindDesired {
            vm_id: VM.into(),
            resource_id: "res-1".into(),
            address: "203.0.113.7/32".into(),
            ..Default::default()
        });
    h.mock.expect_connected(WAIT).await;
    h.mock
        .expect(WAIT, |p| matches!(p, Up::WgSyncRequest(_)).then_some(()))
        .await;
    for _ in 0..50 {
        if h.fake.wg.lock().unwrap().len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(h.fake.wg.lock().unwrap()[0].resource_id, "res-1");
}

#[tokio::test]
async fn console_round_trip() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    h.mock.expect_connected(WAIT).await;
    h.mock.send("c1", create(VM)).await;
    assert!(result_for(&mut h.mock, "c1").await.success);

    let open = Down::ConsoleOpen(proto::CmdConsoleOpen {
        vm_id: VM.into(),
        session_id: "s1".into(),
        cols: 80,
        rows: 24,
    });
    h.mock.send("", open).await;
    let ev = |want: ConsoleEventType| {
        move |p: &Up| match p {
            Up::ConsoleEvent(e) if e.session_id == "s1" && e.r#type == want as i32 => Some(()),
            Up::CmdResult(r) if r.command_id.is_empty() => panic!("console frame was acknowledged"),
            _ => None,
        }
    };
    h.mock
        .expect(WAIT, ev(ConsoleEventType::ConsoleEventConnected))
        .await;

    h.mock
        .send(
            "",
            Down::ConsoleInput(proto::CmdConsoleInput {
                session_id: "s1".into(),
                data: b"ls\r".to_vec(),
            }),
        )
        .await;
    let out = h
        .mock
        .expect(WAIT, |p| match p {
            Up::ConsoleOutput(o) if o.session_id == "s1" => Some(o.data.clone()),
            _ => None,
        })
        .await;
    assert_eq!(out, b"ls\r");

    h.mock
        .send(
            "",
            Down::ConsoleClose(proto::CmdConsoleClose {
                session_id: "s1".into(),
            }),
        )
        .await;
    h.mock
        .expect(WAIT, ev(ConsoleEventType::ConsoleEventDisconnected))
        .await;
}

#[tokio::test]
async fn console_on_unknown_vm_reports_error() {
    let mut h = start(Some(Duration::from_millis(100)), fast()).await;
    h.mock.expect_connected(WAIT).await;
    let open = Down::ConsoleOpen(proto::CmdConsoleOpen {
        vm_id: VM.into(),
        session_id: "s2".into(),
        cols: 80,
        rows: 24,
    });
    h.mock.send("", open).await;
    let reason = h
        .mock
        .expect(WAIT, |p| match p {
            Up::ConsoleEvent(e) if e.session_id == "s2" => {
                assert_eq!(e.r#type, ConsoleEventType::ConsoleEventError as i32);
                Some(e.reason.clone())
            }
            _ => None,
        })
        .await;
    assert!(reason.contains("not found"), "{reason}");
}
