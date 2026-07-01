//! Transport to NetEdge: a persistent WebSocket for near-real-time command
//! push, with automatic fallback to HTTP polling when the WebSocket can't be
//! established (restrictive networks / proxies). The server keeps a per-agent
//! command queue; on every (re)connect the agent first drains it over HTTP, so
//! commands issued while the agent was offline are delivered on reconnect.
//!
//! Wire endpoints (documented in README.md):
//!   POST {base}/api/v1/agents/enroll                      -> EnrollResponse
//!   GET  {base}/api/v1/agents/{id}/commands/poll          -> [ServerMessage]
//!   POST {base}/api/v1/agents/{id}/messages   (AgentMessage body)
//!   WS   {ws_base}/api/v1/agents/{id}/ws

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::Connector;

use netagent_proto::messages::{AgentMessage, EnrollRequest, EnrollResponse, ServerMessage};

use crate::error::{CoreError, Result};

/// Build a reqwest client that pins the server SPKI for https, or a plain
/// client for http. Shared by the transport, enrollment, and the dispatcher's
/// snapin/self-update downloads so they all honor the same pin.
pub fn build_http_client(server_url: &str, spki_pin: Option<&str>) -> Result<reqwest::Client> {
    let is_tls = server_url.starts_with("https://") || server_url.starts_with("wss://");
    if is_tls {
        let pin = spki_pin.ok_or_else(|| CoreError::Tls("spki pin required for TLS".into()))?;
        let cfg =
            crate::tls::pinned_client_config(pin).map_err(|e| CoreError::Tls(e.to_string()))?;
        reqwest::Client::builder()
            .use_preconfigured_tls(cfg)
            .build()
            .map_err(|e| CoreError::Http(e.to_string()))
    } else {
        Ok(reqwest::Client::new())
    }
}

/// HTTP + WS endpoints for one agent.
#[derive(Clone)]
pub struct Transport {
    http: reqwest::Client,
    base: String,   // http(s)://host:port (no trailing slash)
    ws_url: String, // ws(s)://host:port/api/v1/agents/{id}/ws
    agent_id: String,
    ws_connector: Option<Connector>,
    prefer_ws: bool,
}

impl Transport {
    /// Build a transport. `spki_pin` is required for https/wss and used for
    /// public-key pinning (both the HTTP client and the WS connector).
    pub fn new(server_url: &str, agent_id: &str, spki_pin: Option<&str>) -> Result<Self> {
        let base = server_url.trim_end_matches('/').to_string();
        let is_tls = base.starts_with("https://") || base.starts_with("wss://");

        let http = build_http_client(&base, spki_pin)?;
        let ws_connector = if is_tls {
            let pin = spki_pin.ok_or_else(|| CoreError::Tls("spki pin required for TLS".into()))?;
            let cfg =
                crate::tls::pinned_client_config(pin).map_err(|e| CoreError::Tls(e.to_string()))?;
            Some(Connector::Rustls(std::sync::Arc::new(cfg)))
        } else {
            None
        };

        let ws_url = {
            let ws_base = base
                .replacen("https://", "wss://", 1)
                .replacen("http://", "ws://", 1);
            format!("{ws_base}/api/v1/agents/{agent_id}/ws")
        };

        Ok(Self {
            http,
            base,
            ws_url,
            agent_id: agent_id.to_string(),
            ws_connector,
            prefer_ws: true,
        })
    }

    /// For tests / restrictive environments: force HTTP polling, never try WS.
    pub fn with_prefer_ws(mut self, prefer: bool) -> Self {
        self.prefer_ws = prefer;
        self
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// One-shot enrollment POST. Static helper because it runs before an
    /// `agent_id` exists; builds its own (pinned) client.
    pub async fn enroll(
        server_url: &str,
        spki_pin: Option<&str>,
        req: &EnrollRequest,
    ) -> Result<EnrollResponse> {
        let base = server_url.trim_end_matches('/');
        let client = build_http_client(base, spki_pin)?;
        let url = format!("{base}/api/v1/agents/enroll");
        let resp = client
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| CoreError::Enroll(e.to_string()))?;
        if !resp.status().is_success() {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CoreError::Enroll(format!("server returned {code}: {body}")));
        }
        resp.json::<EnrollResponse>()
            .await
            .map_err(|e| CoreError::Enroll(e.to_string()))
    }

    /// POST one agent message (ack/result/rejected/heartbeat) over HTTP.
    pub async fn post_message(&self, msg: &AgentMessage) -> Result<()> {
        let url = format!("{}/api/v1/agents/{}/messages", self.base, self.agent_id);
        let resp = self
            .http
            .post(&url)
            .json(msg)
            .send()
            .await
            .map_err(|e| CoreError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(CoreError::Http(format!(
                "messages endpoint returned {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Drain the server-side command queue over HTTP.
    pub async fn poll_commands(&self) -> Result<Vec<ServerMessage>> {
        let url = format!(
            "{}/api/v1/agents/{}/commands/poll",
            self.base, self.agent_id
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(CoreError::Http(format!(
                "poll endpoint returned {}",
                resp.status()
            )));
        }
        resp.json::<Vec<ServerMessage>>()
            .await
            .map_err(|e| CoreError::Http(e.to_string()))
    }

    /// Run the connection until shutdown: prefer WS, fall back to polling, with
    /// exponential backoff between attempts. `inbound` receives every
    /// `ServerMessage`; `outbound` is drained and delivered (WS frame or POST).
    /// Returns when `outbound` is closed (agent shutting down).
    pub async fn run(
        self,
        inbound: mpsc::UnboundedSender<ServerMessage>,
        mut outbound: mpsc::UnboundedReceiver<AgentMessage>,
        poll_interval: Duration,
    ) {
        let mut backoff = 1u64;
        loop {
            let connected = if self.prefer_ws {
                match self.ws_session(&inbound, &mut outbound).await {
                    Ok(graceful) => {
                        if graceful {
                            return; // outbound closed → shutdown
                        }
                        true
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "websocket session failed; falling back to polling");
                        false
                    }
                }
            } else {
                false
            };

            if !connected {
                // Poll for a bounded burst, then loop back and retry WS.
                match self
                    .poll_session(&inbound, &mut outbound, poll_interval, 6)
                    .await
                {
                    SessionEnd::Shutdown => return,
                    SessionEnd::Continue => {}
                }
            }

            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
            if connected {
                backoff = 1; // reset after a healthy session
            }
        }
    }

    /// One WebSocket session. On connect: drain the queue over HTTP, send Hello,
    /// then multiplex inbound frames and outbound messages until disconnect.
    /// Returns Ok(true) if outbound closed (shutdown), Ok(false) on disconnect.
    async fn ws_session(
        &self,
        inbound: &mpsc::UnboundedSender<ServerMessage>,
        outbound: &mut mpsc::UnboundedReceiver<AgentMessage>,
    ) -> Result<bool> {
        let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
            &self.ws_url,
            None,
            false,
            self.ws_connector.clone(),
        )
        .await
        .map_err(|e| CoreError::Transport(format!("ws connect: {e}")))?;

        // Drain anything queued while we were away, before serving live pushes.
        if let Ok(queued) = self.poll_commands().await {
            for sm in queued {
                let _ = inbound.send(sm);
            }
        }

        let (mut sink, mut stream) = ws.split();
        let hello = AgentMessage::Hello {
            agent_id: self.agent_id.clone(),
        };
        sink.send(WsMessage::Text(json(&hello)?))
            .await
            .map_err(|e| CoreError::Transport(e.to_string()))?;

        loop {
            tokio::select! {
                frame = stream.next() => match frame {
                    Some(Ok(WsMessage::Text(t))) => {
                        if let Ok(sm) = serde_json::from_str::<ServerMessage>(&t) {
                            let _ = inbound.send(sm);
                        }
                    }
                    Some(Ok(WsMessage::Ping(p))) => {
                        let _ = sink.send(WsMessage::Pong(p)).await;
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(false),
                    Some(Err(e)) => return Err(CoreError::Transport(format!("ws read: {e}"))),
                    _ => {}
                },
                out = outbound.recv() => match out {
                    Some(m) => sink.send(WsMessage::Text(json(&m)?)).await
                        .map_err(|e| CoreError::Transport(e.to_string()))?,
                    None => {
                        let _ = sink.send(WsMessage::Close(None)).await;
                        return Ok(true);
                    }
                }
            }
        }
    }

    /// Poll-mode session: alternate draining the command queue and flushing
    /// outbound messages over HTTP for up to `bursts` cycles.
    async fn poll_session(
        &self,
        inbound: &mpsc::UnboundedSender<ServerMessage>,
        outbound: &mut mpsc::UnboundedReceiver<AgentMessage>,
        interval: Duration,
        bursts: u32,
    ) -> SessionEnd {
        for _ in 0..bursts {
            // Flush any pending outbound first.
            while let Ok(msg) = outbound.try_recv() {
                if let Err(e) = self.post_message(&msg).await {
                    tracing::warn!(error = %e, "post_message failed in poll mode");
                }
            }
            match self.poll_commands().await {
                Ok(cmds) => {
                    for sm in cmds {
                        let _ = inbound.send(sm);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "poll_commands failed");
                }
            }
            // Sleep, but wake early (and flush) if an outbound message arrives.
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                out = outbound.recv() => match out {
                    Some(msg) => {
                        if let Err(e) = self.post_message(&msg).await {
                            tracing::warn!(error = %e, "post_message failed in poll mode");
                        }
                    }
                    None => return SessionEnd::Shutdown,
                }
            }
        }
        SessionEnd::Continue
    }
}

enum SessionEnd {
    Continue,
    Shutdown,
}

fn json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| CoreError::Serde(e.to_string()))
}
