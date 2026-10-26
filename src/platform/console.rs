//! Console sessions for one platform stream.
//!
//! Input/resize frames are handled on the receive loop and must never block
//! it: frames for a stalled TTY are dropped, as in the Go agent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::envelope;
use crate::backend::Instances;
use crate::model::{ConsoleSize, VmId};
use crate::proto::agent_envelope::Payload as Up;
use crate::proto::{AgentEnvelope, CmdConsoleOpen, ConsoleEvent, ConsoleEventType, ConsoleOutput};

struct Session {
    input: mpsc::Sender<Vec<u8>>,
    resize: mpsc::Sender<ConsoleSize>,
    cancel: CancellationToken,
}

#[derive(Clone)]
pub struct Consoles {
    instances: Arc<dyn Instances>,
    tx: mpsc::Sender<AgentEnvelope>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// Cancelled when the stream ends; closes every session.
    all: CancellationToken,
}

impl Consoles {
    pub fn new(instances: Arc<dyn Instances>, tx: mpsc::Sender<AgentEnvelope>) -> Self {
        Self {
            instances,
            tx,
            sessions: Arc::default(),
            all: CancellationToken::new(),
        }
    }

    pub fn open(&self, cmd: CmdConsoleOpen) {
        let this = self.clone();
        tokio::spawn(async move { this.run(cmd).await });
    }

    async fn run(self, cmd: CmdConsoleOpen) {
        let sid = cmd.session_id.clone();
        let id = match VmId::parse(&cmd.vm_id) {
            Ok(id) => id,
            Err(e) => {
                return self
                    .event(&sid, ConsoleEventType::ConsoleEventError, format!("{e:#}"))
                    .await;
            }
        };
        if self.sessions.lock().unwrap().contains_key(&sid) {
            return self
                .event(
                    &sid,
                    ConsoleEventType::ConsoleEventError,
                    "duplicate session_id".into(),
                )
                .await;
        }
        let size = ConsoleSize::new(cmd.cols, cmd.rows);
        let mut io = match self.instances.open_console(&id, size).await {
            Ok(io) => io,
            Err(e) => {
                return self
                    .event(&sid, ConsoleEventType::ConsoleEventError, format!("{e:#}"))
                    .await;
            }
        };

        let cancel = self.all.child_token();
        self.sessions.lock().unwrap().insert(
            sid.clone(),
            Session {
                input: io.input.clone(),
                resize: io.resize.clone(),
                cancel: cancel.clone(),
            },
        );
        drop(io.input);
        self.event(&sid, ConsoleEventType::ConsoleEventConnected, String::new())
            .await;

        let reason = loop {
            tokio::select! {
                _ = cancel.cancelled() => break None,
                chunk = io.output.recv() => match chunk {
                    Some(data) => {
                        let out = Up::ConsoleOutput(ConsoleOutput { session_id: sid.clone(), data });
                        if self.tx.send(envelope(out)).await.is_err() {
                            break None;
                        }
                    }
                    None => break Some(String::new()),
                },
            }
        };
        // Dropping the session's input sender tells the backend to detach.
        self.sessions.lock().unwrap().remove(&sid);
        debug!("console {sid} closed");
        self.event(
            &sid,
            ConsoleEventType::ConsoleEventDisconnected,
            reason.unwrap_or_default(),
        )
        .await;
    }

    pub fn input(&self, sid: &str, data: Vec<u8>) {
        if let Some(s) = self.sessions.lock().unwrap().get(sid) {
            let _ = s.input.try_send(data);
        }
    }

    pub fn resize(&self, sid: &str, cols: u32, rows: u32) {
        let (Some(s), Some(size)) = (
            self.sessions
                .lock()
                .unwrap()
                .get(sid)
                .map(|s| s.resize.clone()),
            ConsoleSize::new(cols, rows),
        ) else {
            return;
        };
        let _ = s.try_send(size);
    }

    pub fn close(&self, sid: &str) {
        if let Some(s) = self.sessions.lock().unwrap().get(sid) {
            s.cancel.cancel();
        }
    }

    pub fn close_all(&self) {
        self.all.cancel();
    }

    async fn event(&self, sid: &str, kind: ConsoleEventType, reason: String) {
        let ev = Up::ConsoleEvent(ConsoleEvent {
            session_id: sid.to_owned(),
            r#type: kind as i32,
            reason,
        });
        let _ = self.tx.send(envelope(ev)).await;
    }
}
