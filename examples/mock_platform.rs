//! Minimal stand-in for the platform, for manual end-to-end testing.
//!
//! ```sh
//! cargo run --example mock_platform -- 127.0.0.1:50051
//! ```
//! Point the agent at `platform_url = "http://127.0.0.1:50051"` (any token is
//! accepted), then type commands on stdin:
//!
//! ```text
//! create <vm-uuid> <image> <root-password> [cpu ram_mb disk_gb bw_mbps]
//! reinstall <vm-uuid> <image> <root-password>
//! start|stop|kill|restart|delete <vm-uuid>
//! password <vm-uuid> <new-password>
//! fwd <vm-uuid> <tcp|udp> <host-port> <guest-port>
//! unfwd <vm-uuid> <tcp|udp> <host-port>
//! fwds <vm-uuid>
//! wg <vm-uuid> <resource-id> <wg-quick.conf>   (adds to the desired set)
//! wgclear                                      (empty desired set)
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use runman_agent::proto::agent_envelope::Payload as Up;
use runman_agent::proto::agent_gateway_server::{AgentGateway, AgentGatewayServer};
use runman_agent::proto::platform_envelope::Payload as Down;
use runman_agent::proto::*;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

type Downlink = mpsc::Sender<Result<PlatformEnvelope, Status>>;

#[derive(Clone, Default)]
struct Platform {
    agent: Arc<Mutex<Option<Downlink>>>,
    wg: Arc<Mutex<Vec<WgBindDesired>>>,
}

#[tonic::async_trait]
impl AgentGateway for Platform {
    type ConnectStream = ReceiverStream<Result<PlatformEnvelope, Status>>;

    async fn connect(
        &self,
        req: Request<Streaming<AgentEnvelope>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let auth = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        println!(
            "< agent connected ({})",
            auth.split(' ').next().unwrap_or("no auth")
        );
        let (tx, rx) = mpsc::channel(64);
        *self.agent.lock().unwrap() = Some(tx.clone());
        let ping = tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let env = PlatformEnvelope {
                    command_id: String::new(),
                    payload: Some(Down::Ping(Ping {})),
                };
                if ping.send(Ok(env)).await.is_err() {
                    return;
                }
            }
        });
        let mut up = req.into_inner();
        let wg = self.wg.clone();
        tokio::spawn(async move {
            while let Ok(Some(msg)) = up.message().await {
                match msg.payload {
                    Some(Up::Heartbeat(hb)) => {
                        let vms: Vec<String> = hb
                            .vms
                            .iter()
                            .map(|v| format!("{}={}{:?}", &v.vm_id[..8], v.status, v.ips))
                            .collect();
                        println!(
                            "< heartbeat cpu={:.1}% ram={}/{}MB images={} vms=[{}]",
                            hb.cpu_pct,
                            hb.ram_used_mb,
                            hb.ram_total_mb,
                            hb.os_images.len(),
                            vms.join(" ")
                        );
                    }
                    Some(Up::CmdResult(r)) => {
                        println!(
                            "< result {} success={} {}",
                            r.command_id, r.success, r.error
                        )
                    }
                    Some(Up::PortFwdList(l)) => println!("< port forwards {:?}", l.entries),
                    Some(Up::WgSyncRequest(r)) => {
                        let bindings = wg.lock().unwrap().clone();
                        let env = PlatformEnvelope {
                            command_id: String::new(),
                            payload: Some(Down::WgSyncResponse(WgSyncResponse {
                                request_id: r.request_id,
                                bindings,
                            })),
                        };
                        let _ = tx.send(Ok(env)).await;
                    }
                    other => println!("< {other:?}"),
                }
            }
            println!("< agent disconnected");
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn parse(line: &str, wg: &Mutex<Vec<WgBindDesired>>) -> Result<Option<Down>, String> {
    let w: Vec<&str> = line.split_whitespace().collect();
    let arg = |i: usize| {
        w.get(i)
            .copied()
            .ok_or_else(|| format!("missing argument {i}"))
    };
    let num = |i: usize, d: i64| {
        w.get(i)
            .map_or(Ok(d), |v| v.parse::<i64>().map_err(|e| e.to_string()))
    };
    let proto = |s: &str| {
        if s == "udp" {
            Protocol::Udp as i32
        } else {
            Protocol::Tcp as i32
        }
    };
    let vm = || arg(1).map(str::to_owned);
    Ok(Some(match *w.first().unwrap_or(&"") {
        "" => return Ok(None),
        "create" => Down::CreateVm(CmdCreateVm {
            vm_id: vm()?,
            os_image: arg(2)?.into(),
            root_password: arg(3)?.into(),
            cpu: num(4, 1)? as i32,
            ram_mb: num(5, 512)?,
            disk_gb: num(6, 5)?,
            bandwidth_mbps: num(7, 0)? as i32,
        }),
        "reinstall" => Down::ReinstallVm(CmdReinstallVm {
            vm_id: vm()?,
            os_image: arg(2)?.into(),
            root_password: arg(3)?.into(),
            cpu: 1,
            ram_mb: 512,
            disk_gb: 5,
            bandwidth_mbps: 0,
        }),
        "start" => Down::StartVm(CmdStartVm { vm_id: vm()? }),
        "stop" => Down::StopVm(CmdStopVm {
            vm_id: vm()?,
            force: false,
        }),
        "kill" => Down::StopVm(CmdStopVm {
            vm_id: vm()?,
            force: true,
        }),
        "restart" => Down::RestartVm(CmdRestartVm { vm_id: vm()? }),
        "delete" => Down::DeleteVm(CmdDeleteVm { vm_id: vm()? }),
        "password" => Down::ResetPassword(CmdResetPassword {
            vm_id: vm()?,
            new_password: arg(2)?.into(),
        }),
        "fwd" => Down::SetPortFwd(CmdSetPortForward {
            vm_id: vm()?,
            protocol: proto(arg(2)?),
            host_port: num(3, 0)? as i32,
            guest_port: num(4, 0)? as i32,
            description: "mock".into(),
        }),
        "unfwd" => Down::DelPortFwd(CmdDelPortForward {
            vm_id: vm()?,
            protocol: proto(arg(2)?),
            host_port: num(3, 0)? as i32,
        }),
        "fwds" => Down::GetPortFwds(CmdGetPortForwards { vm_id: vm()? }),
        "wg" => {
            let text = std::fs::read_to_string(arg(3)?).map_err(|e| e.to_string())?;
            let get = |key: &str| {
                text.lines()
                    .find_map(|l| {
                        l.split_once('=')
                            .filter(|(k, _)| k.trim() == key)
                            .map(|(_, v)| v.trim().to_owned())
                    })
                    .unwrap_or_default()
            };
            wg.lock().unwrap().push(WgBindDesired {
                vm_id: vm()?,
                resource_id: arg(2)?.into(),
                private_key: get("PrivateKey"),
                address: get("Address"),
                peer_public_key: get("PublicKey"),
                preshared_key: get("PresharedKey"),
                endpoint: get("Endpoint"),
                allowed_ips: vec![get("AllowedIPs")],
                keepalive_sec: get("PersistentKeepalive").parse().unwrap_or(25),
            });
            println!(
                "> wg desired set now has {} binding(s); applied on the next sync",
                wg.lock().unwrap().len()
            );
            return Ok(None);
        }
        "wgclear" => {
            wg.lock().unwrap().clear();
            println!("> wg desired set cleared");
            return Ok(None);
        }
        other => return Err(format!("unknown command {other:?}")),
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:50051".into())
        .parse()?;
    let platform = Platform::default();
    let server = platform.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AgentGatewayServer::new(server))
            .serve(addr)
            .await
            .unwrap();
    });
    println!("mock platform on {addr}; type commands (see source header)");
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut n = 0;
    while let Some(line) = lines.next_line().await? {
        match parse(line.trim(), &platform.wg) {
            Ok(Some(payload)) => {
                n += 1;
                let command_id = format!("cmd-{n}");
                let tx = platform.agent.lock().unwrap().clone();
                match tx {
                    Some(tx) => {
                        let _ = tx
                            .send(Ok(PlatformEnvelope {
                                command_id: command_id.clone(),
                                payload: Some(payload),
                            }))
                            .await;
                        println!("> sent {command_id}");
                    }
                    None => println!("! no agent connected"),
                }
            }
            Ok(None) => {}
            Err(e) => println!("! {e}"),
        }
    }
    Ok(())
}
