//! Interactive remote shell sessions.
//!
//! On `OpenShell` the agent spawns a real PTY and streams its output back to
//! NetEdge as `ShellOutput` messages over the same transport that carries
//! commands; operator keystrokes arrive as `ShellInput`. This mirrors the
//! JWT-over-WebSocket console UX NetEdge already uses for ttyd, so the operator
//! gets one consistent console during *and* after deployment.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;

use base64::Engine as _;
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use tokio::sync::mpsc::UnboundedSender;

use netagent_proto::messages::AgentMessage;

struct Session {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    _master: Box<dyn MasterPty + Send>,
}

/// Tracks open PTY sessions keyed by `session_id`.
pub struct ShellManager {
    out: UnboundedSender<AgentMessage>,
    sessions: Mutex<HashMap<String, Session>>,
}

impl ShellManager {
    pub fn new(out: UnboundedSender<AgentMessage>) -> Self {
        Self {
            out,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Open a new shell session; idempotent for a repeated id.
    pub fn open(&self, session_id: &str) -> std::io::Result<()> {
        if self.sessions.lock().contains_key(session_id) {
            return Ok(());
        }
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(to_io)?;

        let cmd = CommandBuilder::new(default_shell());
        let child = pair.slave.spawn_command(cmd).map_err(to_io)?;
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().map_err(to_io)?;
        let writer = pair.master.take_writer().map_err(to_io)?;

        // Reader runs on a blocking thread, forwarding output as base64 frames.
        let out = self.out.clone();
        let sid = session_id.to_string();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&buf[..n]);
                        if out
                            .send(AgentMessage::ShellOutput {
                                session_id: sid.clone(),
                                data_b64,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = out.send(AgentMessage::ShellClosed {
                session_id: sid.clone(),
            });
        });

        self.sessions.lock().insert(
            session_id.to_string(),
            Session {
                writer: Arc::new(Mutex::new(writer)),
                child: Arc::new(Mutex::new(child)),
                _master: pair.master,
            },
        );
        Ok(())
    }

    /// Feed operator input (base64) to a session's PTY.
    pub fn feed(&self, session_id: &str, data_b64: &str) {
        let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(b) => b,
            Err(_) => return,
        };
        let writer = {
            self.sessions
                .lock()
                .get(session_id)
                .map(|s| s.writer.clone())
        };
        if let Some(w) = writer {
            let mut guard = w.lock();
            let _ = guard.write_all(&bytes);
            let _ = guard.flush();
        }
    }

    /// Close and kill a session.
    pub fn close(&self, session_id: &str) {
        if let Some(s) = self.sessions.lock().remove(session_id) {
            let _ = s.child.lock().kill();
        }
    }
}

fn default_shell() -> String {
    #[cfg(windows)]
    {
        std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_string())
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

fn to_io(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
