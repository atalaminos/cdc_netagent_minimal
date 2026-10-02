//! A minimal in-process NetEdge stand-in for integration tests.
//!
//! Implements the server half of the Netagent protocol: enrollment, the
//! per-agent command queue, the HTTP poll + messages endpoints, and the
//! WebSocket push channel. It signs commands with a test "command key" (whose
//! public half it hands the agent at enrollment) and verifies every agent
//! report against the agent's enrolled public key — exercising both directions
//! of the trust model. Not a production server.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use tokio::sync::mpsc;
use uuid::Uuid;

use netagent_proto::command::{
    sign_command, Command, CommandEnvelope, SignedCommand, PROTOCOL_VERSION,
};
use netagent_proto::crypto::{generate_signing_key, verifying_key_from_hex, verifying_key_to_hex};
use netagent_proto::messages::{
    poll_auth, AgentMessage, CommandAck, CommandResult, EnrollRequest, EnrollResponse, Heartbeat,
    RejectedCommandReport, ServerMessage, SignedReport,
};
use netagent_proto::now_unix;

struct AgentRecord {
    pubkey: VerifyingKey,
    #[allow(dead_code)]
    hostname: String,
    /// Last accepted poll timestamp (ms) — polls must be strictly newer.
    last_poll_ts: i64,
}

/// Server-side state, shared across handlers and the test handle.
pub struct MockState {
    enrollment_token: String,
    command_key: SigningKey,
    command_pubkey_hex: String,
    spki_pin: Option<String>,
    agents: Mutex<HashMap<String, AgentRecord>>,
    queues: Mutex<HashMap<String, VecDeque<ServerMessage>>>,
    ws_senders: Mutex<HashMap<String, mpsc::UnboundedSender<ServerMessage>>>,
    inbox: Mutex<Vec<AgentMessage>>,
    rejected_reports: Mutex<u32>,
    rejected_polls: Mutex<u32>,
    accepted_polls: Mutex<u32>,
}

impl MockState {
    fn new() -> Self {
        let command_key = generate_signing_key();
        let command_pubkey_hex = verifying_key_to_hex(&command_key.verifying_key());
        Self {
            enrollment_token: "test-enrollment-token".to_string(),
            command_key,
            command_pubkey_hex,
            spki_pin: None,
            agents: Mutex::new(HashMap::new()),
            queues: Mutex::new(HashMap::new()),
            ws_senders: Mutex::new(HashMap::new()),
            inbox: Mutex::new(Vec::new()),
            rejected_reports: Mutex::new(0),
            rejected_polls: Mutex::new(0),
            accepted_polls: Mutex::new(0),
        }
    }

    /// Deliver a server message: over a live WS if the agent is connected,
    /// otherwise enqueue for the next poll (offline delivery on reconnect).
    fn enqueue(&self, agent_id: &str, sm: ServerMessage) {
        let via_ws = {
            let senders = self.ws_senders.lock();
            match senders.get(agent_id) {
                Some(tx) => tx.send(sm.clone()).is_ok(),
                None => false,
            }
        };
        if !via_ws {
            self.queues
                .lock()
                .entry(agent_id.to_string())
                .or_default()
                .push_back(sm);
        }
    }

    /// Record an inbound agent message, verifying signed reports against the
    /// agent's enrolled key. Unverifiable reports are counted, not recorded.
    fn ingest(&self, agent_id: &str, msg: AgentMessage) {
        let ok = match &msg {
            AgentMessage::Ack(s) => self.verify(agent_id, s),
            AgentMessage::Result(s) => self.verify(agent_id, s),
            AgentMessage::Rejected(s) => self.verify(agent_id, s),
            AgentMessage::Heartbeat(s) => self.verify(agent_id, s),
            _ => true,
        };
        if ok {
            self.inbox.lock().push(msg);
        } else {
            *self.rejected_reports.lock() += 1;
        }
    }

    fn verify<T: serde::Serialize + DeserializeOwned>(
        &self,
        agent_id: &str,
        s: &SignedReport<T>,
    ) -> bool {
        let agents = self.agents.lock();
        match agents.get(agent_id) {
            Some(rec) => netagent_proto::messages::verify_report(s, &rec.pubkey).is_ok(),
            None => false,
        }
    }
}

/// Test handle: owns the server task and exposes helpers for crafting commands
/// and inspecting what the agent reported back.
pub struct MockServer {
    pub base_url: String,
    state: Arc<MockState>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockServer {
    /// Start a server with the WebSocket route enabled.
    pub async fn start() -> Self {
        Self::start_inner(true).await
    }

    /// Start a server WITHOUT the WebSocket route, so the agent's WS connect
    /// fails and it must fall back to HTTP polling (restrictive-network test).
    pub async fn start_without_ws() -> Self {
        Self::start_inner(false).await
    }

    async fn start_inner(with_ws: bool) -> Self {
        let state = Arc::new(MockState::new());
        let mut app = Router::new()
            .route("/api/v1/agents/enroll", post(enroll))
            .route("/api/v1/agents/:id/commands/poll", get(poll))
            .route("/api/v1/agents/:id/messages", post(messages));
        if with_ws {
            app = app.route("/api/v1/agents/:id/ws", get(ws_handler));
        }
        let app = app.with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockServer {
            base_url: format!("http://{addr}"),
            state,
            _task: task,
        }
    }

    pub fn enrollment_token(&self) -> &str {
        &self.state.enrollment_token
    }
    pub fn command_pubkey_hex(&self) -> String {
        self.state.command_pubkey_hex.clone()
    }
    pub fn spki_pin(&self) -> Option<String> {
        self.state.spki_pin.clone()
    }

    /// Build a well-formed envelope for `agent_id` (caller can mutate before signing).
    pub fn make_envelope(
        &self,
        agent_id: &str,
        command: Command,
        issued_at: i64,
        ttl: i64,
    ) -> CommandEnvelope {
        CommandEnvelope {
            version: PROTOCOL_VERSION,
            command_id: Uuid::new_v4(),
            agent_id: agent_id.to_string(),
            command,
            issued_at,
            expires_at: issued_at + ttl,
            nonce: rand_nonce(),
        }
    }

    /// Sign an envelope with the server's command key.
    pub fn sign(&self, env: CommandEnvelope) -> SignedCommand {
        sign_command(env, &self.state.command_key).expect("sign command")
    }

    /// Convenience: build + sign a valid command (now, 30s window) and deliver it.
    pub fn enqueue_command(&self, agent_id: &str, command: Command) -> Uuid {
        let env = self.make_envelope(agent_id, command, now_unix(), 30);
        let id = env.command_id;
        let signed = self.sign(env);
        self.enqueue_signed(agent_id, signed);
        id
    }

    /// Deliver an already-signed command (used to inject invalid/expired/replay).
    pub fn enqueue_signed(&self, agent_id: &str, signed: SignedCommand) {
        self.state
            .enqueue(agent_id, ServerMessage::Command(Box::new(signed)));
    }

    /// Deliver an arbitrary server message (e.g. shell input).
    pub fn enqueue_message(&self, agent_id: &str, sm: ServerMessage) {
        self.state.enqueue(agent_id, sm);
    }

    pub fn is_connected(&self, agent_id: &str) -> bool {
        self.state.ws_senders.lock().contains_key(agent_id)
    }
    /// Ids of all agents that have enrolled.
    pub fn agent_ids(&self) -> Vec<String> {
        self.state.agents.lock().keys().cloned().collect()
    }
    pub fn rejected_report_count(&self) -> u32 {
        *self.state.rejected_reports.lock()
    }
    /// Polls refused for a missing/invalid/stale/replayed signature.
    pub fn rejected_poll_count(&self) -> u32 {
        *self.state.rejected_polls.lock()
    }
    /// Polls accepted (valid signature).
    pub fn accepted_poll_count(&self) -> u32 {
        *self.state.accepted_polls.lock()
    }

    pub fn results(&self) -> Vec<CommandResult> {
        self.collect(|m| match m {
            AgentMessage::Result(s) => Some(s.body.inner.clone()),
            _ => None,
        })
    }
    pub fn acks(&self) -> Vec<CommandAck> {
        self.collect(|m| match m {
            AgentMessage::Ack(s) => Some(s.body.inner.clone()),
            _ => None,
        })
    }
    pub fn rejections(&self) -> Vec<RejectedCommandReport> {
        self.collect(|m| match m {
            AgentMessage::Rejected(s) => Some(s.body.inner.clone()),
            _ => None,
        })
    }
    pub fn heartbeats(&self) -> Vec<Heartbeat> {
        self.collect(|m| match m {
            AgentMessage::Heartbeat(s) => Some(s.body.inner.clone()),
            _ => None,
        })
    }
    pub fn shell_output(&self) -> Vec<(String, String)> {
        self.collect(|m| match m {
            AgentMessage::ShellOutput {
                session_id,
                data_b64,
            } => Some((session_id.clone(), data_b64.clone())),
            _ => None,
        })
    }

    fn collect<T>(&self, f: impl Fn(&AgentMessage) -> Option<T>) -> Vec<T> {
        self.state.inbox.lock().iter().filter_map(f).collect()
    }
}

fn rand_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut n = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

// ---- handlers ----

async fn enroll(
    State(st): State<Arc<MockState>>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    if req.enrollment_token != st.enrollment_token {
        return Err((StatusCode::UNAUTHORIZED, "invalid enrollment token".into()));
    }
    let pubkey = verifying_key_from_hex(&req.agent_pubkey)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad agent pubkey: {e}")))?;
    let agent_id = Uuid::new_v4().to_string();
    st.agents.lock().insert(
        agent_id.clone(),
        AgentRecord {
            pubkey,
            hostname: req.hostname,
            last_poll_ts: 0,
        },
    );
    st.queues.lock().insert(agent_id.clone(), VecDeque::new());
    Ok(Json(EnrollResponse {
        agent_id,
        server_command_pubkey: st.command_pubkey_hex.clone(),
        server_spki_pin: st.spki_pin.clone(),
        // Large heartbeat interval so tests aren't perturbed by beats; fast poll.
        heartbeat_interval_secs: 36_000,
        poll_interval_secs: 1,
    }))
}

/// Verify the poll's `x-netagent-ts`/`x-netagent-sig` against the enrolled
/// key, enforcing freshness and strictly increasing timestamps (anti-replay).
fn poll_authorized(st: &MockState, id: &str, headers: &HeaderMap) -> bool {
    let ts = headers
        .get(poll_auth::HEADER_TS)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok());
    let sig = headers
        .get(poll_auth::HEADER_SIG)
        .and_then(|v| v.to_str().ok());
    let (Some(ts), Some(sig)) = (ts, sig) else {
        return false;
    };
    let mut agents = st.agents.lock();
    let Some(rec) = agents.get_mut(id) else {
        return false;
    };
    if ts <= rec.last_poll_ts
        || poll_auth::verify(&rec.pubkey, id, ts, sig, poll_auth::now_ms()).is_err()
    {
        return false;
    }
    rec.last_poll_ts = ts;
    true
}

async fn poll(
    Path(id): Path<String>,
    State(st): State<Arc<MockState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ServerMessage>>, StatusCode> {
    if !poll_authorized(&st, &id, &headers) {
        *st.rejected_polls.lock() += 1;
        return Err(StatusCode::UNAUTHORIZED);
    }
    *st.accepted_polls.lock() += 1;
    let mut q = st.queues.lock();
    let drained: Vec<ServerMessage> = q
        .get_mut(&id)
        .map(|dq| dq.drain(..).collect())
        .unwrap_or_default();
    Ok(Json(drained))
}

async fn messages(
    Path(id): Path<String>,
    State(st): State<Arc<MockState>>,
    Json(msg): Json<AgentMessage>,
) -> StatusCode {
    st.ingest(&id, msg);
    StatusCode::OK
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(id): Path<String>,
    State(st): State<Arc<MockState>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, id, st))
}

async fn handle_ws(socket: WebSocket, id: String, st: Arc<MockState>) {
    let (mut tx, mut rx) = socket.split();
    let (push_tx, mut push_rx) = mpsc::unbounded_channel::<ServerMessage>();
    st.ws_senders.lock().insert(id.clone(), push_tx);

    loop {
        tokio::select! {
            incoming = rx.next() => match incoming {
                Some(Ok(Message::Text(t))) => {
                    if let Ok(am) = serde_json::from_str::<AgentMessage>(&t) {
                        st.ingest(&id, am);
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            push = push_rx.recv() => match push {
                Some(sm) => {
                    let text = serde_json::to_string(&sm).unwrap();
                    if tx.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    }
    st.ws_senders.lock().remove(&id);
}
