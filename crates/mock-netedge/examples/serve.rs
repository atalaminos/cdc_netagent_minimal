//! Run the mock NetEdge server for manual end-to-end testing of the real agent.
//!
//! Usage:
//!   cargo run -p mock-netedge --example serve
//!
//! It prints the base URL + enrollment token to put in the agent config, then
//! waits for an agent to enroll. On the first agent it sees, it pushes a `Ping`
//! and a `GetHardware` command and prints whatever the agent reports back.

use std::collections::HashSet;
use std::time::Duration;

use mock_netedge::MockServer;
use netagent_proto::command::Command;

#[tokio::main]
async fn main() {
    let mock = MockServer::start().await;
    println!("mock-netedge listening at {}", mock.base_url);
    println!("enrollment_token = {}", mock.enrollment_token());
    println!(
        "server_command_pubkey (pin) = {}",
        mock.command_pubkey_hex()
    );
    println!();
    println!("Point an agent config at it, e.g.:");
    println!("  server_url = \"{}\"", mock.base_url);
    println!("  enrollment_token = \"{}\"", mock.enrollment_token());
    println!("  data_dir = \"/tmp/netagent-smoke\"");
    println!();
    println!("Then: netagent --config /tmp/netagent-agent.toml run");
    println!("Waiting for an agent to enroll...\n");

    let mut seen: HashSet<String> = HashSet::new();
    let mut printed_results = 0usize;
    loop {
        for id in mock.agent_ids() {
            if seen.insert(id.clone()) {
                println!("agent enrolled: {id} — pushing Ping + GetHardware");
                mock.enqueue_command(&id, Command::Ping);
                mock.enqueue_command(&id, Command::GetHardware);
            }
        }
        let results = mock.results();
        for r in results.iter().skip(printed_results) {
            println!(
                "result: ok={} msg={:?} data={}",
                r.ok,
                r.message,
                r.data.is_some()
            );
        }
        printed_results = results.len();
        for hb in mock.heartbeats() {
            println!(
                "heartbeat: v{} uptime={}s",
                hb.agent_version, hb.uptime_secs
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
