//! Vectores de compatibilidad byte-exacta con el espejo del protocolo en NetEdge
//! (`src/agent_proto.rs`, módulo `compat_vector`). Si un cambio aquí altera un
//! vector, el espejo de NetEdge debe actualizarse en el mismo cambio.
use ed25519_dalek::SigningKey;
use netagent_proto::command::{sign_command, Command, CommandEnvelope, RebootPolicy, PROTOCOL_VERSION};
use netagent_proto::messages::{CommandResult, ReportBody, ServerMessage};
use uuid::Uuid;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn env(cmd: Command) -> CommandEnvelope {
    CommandEnvelope {
        version: PROTOCOL_VERSION,
        command_id: Uuid::from_bytes([0x11; 16]),
        agent_id: "agent-canonical".into(),
        command: cmd,
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_050,
        nonce: [0x22; 16],
    }
}


pub const EXEC_HEX: &str = "011000000000000000111111111111111111111111111111110f000000000000006167656e742d63616e6f6e6963616c0300000007000000000000002f62696e2f7368020000000000000002000000000000002d6309000000000000006563686f20686f6c611e00000000010000000000000001000000000000004b01000000000000005600f153650000000032f153650000000022222222222222222222222222222222";
pub const SETHOST_HEX: &str = "011000000000000000111111111111111111111111111111110f000000000000006167656e742d63616e6f6e6963616c04000000050000000000000070632d3031020000000500000000f153650000000032f153650000000022222222222222222222222222222222";
pub const REBOOT_HEX: &str = "011000000000000000111111111111111111111111111111110f000000000000006167656e742d63616e6f6e6963616c010000000a00000000f153650000000032f153650000000022222222222222222222222222222222";
pub const RESULT_HEX: &str = "0f000000000000006167656e742d63616e6f6e6963616c64f15365000000003333333333333333333333333333333310000000000000001111111111111111111111111111111101010000000003000000000000006f757400000000000000000400000000000000646f6e655af153650000000000";

/// El layout bincode de los sobres/informes es CONTRATO con NetEdge: estos mismos
/// vectores están fijados en `netedge/src/agent_proto.rs` (`compat_vector`).
#[test]
fn bincode_layout_matches_netedge_mirror() {
    let exec = env(Command::Exec { program: "/bin/sh".into(), args: vec!["-c".into(), "echo hola".into()], timeout_secs: 30, cwd: None, env: vec![("K".into(), "V".into())] });
    assert_eq!(hex(&bincode::serialize(&exec).unwrap()), EXEC_HEX);
    let sh = env(Command::SetHostname { name: "pc-01".into(), reboot: RebootPolicy::Deferred(5) });
    assert_eq!(hex(&bincode::serialize(&sh).unwrap()), SETHOST_HEX);
    let rb = env(Command::Reboot { delay_secs: 10 });
    assert_eq!(hex(&bincode::serialize(&rb).unwrap()), REBOOT_HEX);
    let body = ReportBody { agent_id: "agent-canonical".into(), issued_at: 1_700_000_100, nonce: [0x33; 16],
        inner: CommandResult { command_id: Uuid::from_bytes([0x11; 16]), ok: true, exit_code: Some(0), stdout: "out".into(), stderr: String::new(), message: "done".into(), finished_at: 1_700_000_090, data: None } };
    assert_eq!(hex(&bincode::serialize(&body).unwrap()), RESULT_HEX);
}

/// Forma JSON del poll HTTP: array de `ServerMessage` (variante externamente
/// etiquetada `{"Command": SignedCommand}`), que es lo que NetEdge debe servir.
#[test]
fn poll_json_shape_is_tagged_array() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let signed = sign_command(env(Command::Ping), &key).unwrap();
    let v: serde_json::Value = serde_json::to_value(vec![ServerMessage::Command(Box::new(signed))]).unwrap();
    assert!(v.is_array());
    assert_eq!(v[0]["Command"]["payload"]["command"], "Ping");
    assert_eq!(v[0]["Command"]["signature"].as_array().unwrap().len(), 64);
}
