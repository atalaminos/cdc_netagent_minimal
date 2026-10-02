//! End-to-end tests of the agent against a simulated NetEdge (`mock-netedge`).
//!
//! Covers the trust model and transport contract from README.md:
//!  1. enrollment establishes a per-agent identity + pinned command key
//!  2. a valid signed command executes and is reported
//!  3. an invalid signature is rejected and reported as an attempt
//!  4. a replayed command (same command_id) is rejected
//!  5. an expired / out-of-window command is rejected
//!  6. commands queued while the agent is offline are delivered on connect
//!  7. WebSocket push works, and WS-unavailable falls back to HTTP polling
//!
//! All host actions go through `MockPlatform`, so nothing destructive runs.

use std::sync::Arc;
use std::time::Duration;

use mock_netedge::MockServer;
use netagent_core::{
    Agent, Config, EnrollState, ExecPolicy, Identity, MockPlatform, RuntimeOptions,
};
use netagent_proto::command::{sign_command, Command, RejectReason};
use netagent_proto::crypto::generate_signing_key;
use netagent_proto::now_unix;

fn test_config(mock: &MockServer, dir: &std::path::Path) -> Config {
    Config {
        server_url: mock.base_url.clone(),
        data_dir: dir.to_path_buf(),
        enrollment_token: Some(mock.enrollment_token().to_string()),
        server_spki_pin: None,
        heartbeat_interval_secs: 36_000,
        poll_interval_secs: 1,
        // Tests need exec to run; production default is deny-all.
        exec_policy: ExecPolicy {
            allow_arbitrary: true,
            allow_list: vec![],
        },
        log_level: "info".into(),
    }
}

fn test_identity() -> Identity {
    Identity {
        hostname: "test-host".into(),
        mac: "00:11:22:33:44:55".into(),
        machine_fingerprint: "fp-1".into(),
        os: "linux".into(),
        agent_version: "1.0.0".into(),
    }
}

/// Poll `cond` until true or ~6s elapse.
async fn wait_until<F: Fn() -> bool>(cond: F) -> bool {
    for _ in 0..120 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
}

/// Enroll, then spawn the running agent with a mock platform we keep a handle to.
async fn enroll_and_run(
    mock: &MockServer,
    dir: &std::path::Path,
    prefer_ws: bool,
) -> (EnrollState, Arc<MockPlatform>) {
    let config = test_config(mock, dir);
    let state = netagent_core::enroll(&config, &test_identity())
        .await
        .expect("enroll");
    let platform = Arc::new(MockPlatform::new());
    let dynp: netagent_core::DynPlatform = platform.clone();
    let cfg = config.clone();
    let st = state.clone();
    tokio::spawn(async move {
        let _ = Agent::run_with_state(cfg, st, dynp, "1.0.0", RuntimeOptions { prefer_ws }).await;
    });
    (state, platform)
}

#[tokio::test]
async fn enrollment_establishes_identity_and_pins_command_key() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&mock, dir.path());

    let state = netagent_core::enroll(&config, &test_identity())
        .await
        .expect("enroll");

    assert!(!state.agent_id.is_empty());
    assert_eq!(state.server_command_pubkey, mock.command_pubkey_hex());
    // Key + state were persisted.
    assert!(config.key_path().exists());
    assert!(config.state_path().exists());
}

#[tokio::test]
async fn enrollment_rejects_bad_token() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(&mock, dir.path());
    config.enrollment_token = Some("wrong-token".into());

    let err = netagent_core::enroll(&config, &test_identity()).await;
    assert!(err.is_err(), "enrollment with a bad token must fail");
}

#[tokio::test]
async fn valid_command_executes_and_reports() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, platform) = enroll_and_run(&mock, dir.path(), false).await;

    let cmd_id = mock.enqueue_command(
        &state.agent_id,
        Command::Exec {
            program: "echo".into(),
            args: vec!["hi".into()],
            timeout_secs: 5,
            cwd: None,
            env: vec![],
        },
    );

    assert!(
        wait_until(|| mock
            .results()
            .iter()
            .any(|r| r.command_id == cmd_id && r.ok))
        .await,
        "expected a successful result for the exec command"
    );
    assert!(
        mock.acks().iter().any(|a| a.command_id == cmd_id),
        "expected an ack"
    );
    assert!(
        platform
            .recorded()
            .iter()
            .any(|c| c.starts_with("exec:echo")),
        "platform should have executed the command; recorded={:?}",
        platform.recorded()
    );
}

#[tokio::test]
async fn invalid_signature_is_rejected_and_audited() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, platform) = enroll_and_run(&mock, dir.path(), false).await;

    // Sign with an attacker key the agent does not trust.
    let attacker = generate_signing_key();
    let env = mock.make_envelope(
        &state.agent_id,
        Command::Reboot { delay_secs: 0 },
        now_unix(),
        30,
    );
    let forged = sign_command(env, &attacker).unwrap();
    mock.enqueue_signed(&state.agent_id, forged);

    assert!(
        wait_until(|| mock
            .rejections()
            .iter()
            .any(|r| r.reason == RejectReason::BadSignature))
        .await,
        "expected a BadSignature rejection report"
    );
    // The forged reboot must NOT have been executed.
    assert!(
        !platform.recorded().iter().any(|c| c.starts_with("reboot")),
        "a forged command must never reach the platform"
    );
}

#[tokio::test]
async fn replayed_command_is_rejected() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, _platform) = enroll_and_run(&mock, dir.path(), false).await;

    let signed = mock.sign(mock.make_envelope(&state.agent_id, Command::Ping, now_unix(), 30));
    let cmd_id = signed.payload.command_id;
    mock.enqueue_signed(&state.agent_id, signed.clone());
    mock.enqueue_signed(&state.agent_id, signed); // identical command_id → replay

    assert!(
        wait_until(|| mock
            .rejections()
            .iter()
            .any(|r| r.reason == RejectReason::Replay))
        .await,
        "expected a Replay rejection"
    );
    // The command should have been admitted exactly once.
    let successes = mock
        .results()
        .iter()
        .filter(|r| r.command_id == cmd_id && r.ok)
        .count();
    assert_eq!(successes, 1, "replayed command must execute only once");
}

#[tokio::test]
async fn expired_command_is_rejected() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, _platform) = enroll_and_run(&mock, dir.path(), false).await;

    // issued 100s ago with a 30s window → already expired.
    let env = mock.make_envelope(&state.agent_id, Command::Ping, now_unix() - 100, 30);
    let signed = mock.sign(env);
    mock.enqueue_signed(&state.agent_id, signed);

    assert!(
        wait_until(|| mock
            .rejections()
            .iter()
            .any(|r| r.reason == RejectReason::Expired))
        .await,
        "expected an Expired rejection"
    );
}

#[tokio::test]
async fn commands_queued_while_offline_are_delivered_on_connect() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    // Enroll first, enqueue while the agent is NOT yet running...
    let config = test_config(&mock, dir.path());
    let state = netagent_core::enroll(&config, &test_identity())
        .await
        .unwrap();
    let cmd_id = mock.enqueue_command(&state.agent_id, Command::Ping);

    // ...then start the agent; it must drain the queue on its first poll.
    let platform = Arc::new(MockPlatform::new());
    let dynp: netagent_core::DynPlatform = platform.clone();
    tokio::spawn(async move {
        let _ = Agent::run_with_state(
            config,
            state,
            dynp,
            "1.0.0",
            RuntimeOptions { prefer_ws: false },
        )
        .await;
    });

    assert!(
        wait_until(|| mock
            .results()
            .iter()
            .any(|r| r.command_id == cmd_id && r.ok))
        .await,
        "a command queued before connect must be delivered on connect"
    );
}

#[tokio::test]
async fn websocket_push_delivers_commands() {
    let mock = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, _platform) = enroll_and_run(&mock, dir.path(), true).await;

    // Wait until the agent's WebSocket is connected, then push a command.
    assert!(
        wait_until(|| mock.is_connected(&state.agent_id)).await,
        "agent should connect via WS"
    );
    let cmd_id = mock.enqueue_command(&state.agent_id, Command::Ping);

    assert!(
        wait_until(|| mock
            .results()
            .iter()
            .any(|r| r.command_id == cmd_id && r.ok))
        .await,
        "command pushed over WebSocket should be executed"
    );
}

#[tokio::test]
async fn falls_back_to_polling_when_websocket_unavailable() {
    // Server without a WS route: the agent's WS connect fails and it must poll.
    let mock = MockServer::start_without_ws().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, _platform) = enroll_and_run(&mock, dir.path(), true).await;

    let cmd_id = mock.enqueue_command(&state.agent_id, Command::Ping);
    assert!(
        wait_until(|| mock
            .results()
            .iter()
            .any(|r| r.command_id == cmd_id && r.ok))
        .await,
        "command must still execute via HTTP polling fallback"
    );
    assert!(
        !mock.is_connected(&state.agent_id),
        "no WS should be established"
    );
    // Every poll the agent made was signed and accepted; none was refused.
    assert!(mock.accepted_poll_count() > 0, "agent polls must be signed");
    assert_eq!(mock.rejected_poll_count(), 0, "no poll may fail authentication");
}

#[tokio::test]
async fn unsigned_or_replayed_poll_is_refused() {
    let mock = MockServer::start_without_ws().await;
    let dir = tempfile::tempdir().unwrap();
    let (state, _platform) = enroll_and_run(&mock, dir.path(), true).await;
    let url = format!(
        "{}/api/v1/agents/{}/commands/poll",
        mock.base_url, state.agent_id
    );
    let client = reqwest::Client::new();

    // No signature headers → 401.
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 401);

    // Signed by a foreign key (an attacker who only knows the agent id) → 401.
    use netagent_proto::messages::poll_auth;
    let attacker = generate_signing_key();
    let ts = poll_auth::now_ms() + 60_000;
    let r = client
        .get(&url)
        .header(poll_auth::HEADER_TS, ts.to_string())
        .header(poll_auth::HEADER_SIG, poll_auth::sign(&attacker, &state.agent_id, ts))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(mock.rejected_poll_count() >= 2);
}
