# Netagent

Agente de gestión persistente y multiplataforma (Windows + Linux) para **NetEdge**. Se
ejecuta sobre el sistema operativo ya desplegado — después del clonado, en producción — para
ofrecer gestión remota continua: reinicio/apagado, ejecución de comandos arbitrarios (con
política), cambio de hostname y reconfiguración de red, inventario de drivers de Windows,
telemetría continua de hardware/SMART, inventario de software, despliegue silencioso de
paquetes (snapins), programación de energía en ventana de mantenimiento, shell remota
interactiva y auto-actualización firmada.

Está construido como una **extensión coherente del modelo de confianza Ed25519 de NetEdge**:
cada comando va firmado con Ed25519 y se verifica contra una clave de NetEdge fijada (pin),
con nonce + ventana de validez corta + protección anti-replay — sustituyendo el canal de
control por token estático del servidor de control de netdd. Cada agente tiene su propia
identidad por equipo (revocación granular), la conexión es TLS con pinning de clave pública
del servidor, y la ejecución está denegada por defecto con listas blancas por grupo.

```bash
./build.sh                             # Linux: compila (release) + tests + check de Windows
build.bat                              # Windows: compila (release) + tests (nativo)

cargo build --workspace --release      # compilar (Linux)
cargo test  --workspace                # proto + core + platform + 9 tests de integración E2E
cargo check --workspace --target x86_64-pc-windows-gnu   # comprobación para Windows
```

Este documento es la descripción autoritativa del protocolo agente↔servidor y del modelo
operativo. El lado servidor se ejercita aquí mediante un mock en proceso
(`crates/mock-netedge`); los endpoints reales a implementar en NetEdge están en
[Contrato del lado servidor](#contrato-del-lado-servidor-a-implementar-en-netedge).

---

## Por qué es distinto del canal de control antiguo

NetEdge ya firma sub-licencias de corta duración que netdd verifica contra una clave pública
embebida; Netagent aplica el mismo patrón («firmar un payload bincode con Ed25519, verificar
contra una clave pública fijada») a los **comandos de gestión remota**, sustituyendo el canal
de control por **token estático** (`/control/<cmd>`) que usaba el servidor de control de netdd.

| | Servidor de control de netdd (antiguo) | Netagent |
|---|---|---|
| Auth de un comando | un **token estático** único, compartido, de larga vida | **firma Ed25519** por comando, verificada contra una clave fijada |
| Protección anti-replay | ninguna | **nonce + ventana de validez corta + caché de replay** |
| Identidad por equipo | ninguna (token compartido) | cada agente tiene **su propio par de claves**; se revoca uno sin tocar el resto |
| Transporte | HTTP entrante hacia cada nodo | WS **saliente** (push) + *fallback* a polling HTTP; funciona tras NAT/proxies |
| TLS | HTTP plano | TLS con **pinning de clave pública** del servidor (admite autofirmados) |
| Ejecución arbitraria | siempre permitida si se conoce el token | **denegado por defecto**, lista blanca por grupo, arbitrario solo en grupos admin |

---

## Arquitectura

Un workspace Rust; la lógica de protocolo/confianza es compartida y libre de plataforma, y
todas las acciones sobre el equipo viven tras un único *trait* con implementaciones por SO.

```
crates/
  proto/         núcleo de confianza: SignedCommand, CommandEnvelope, replay, SignedReport,
                 helpers Ed25519 + SPKI. Sin tokio, sin plataforma. (21 tests unitarios)
  core/          runtime: config, verificador de pinning TLS, transporte (WS + fallback poll),
                 dispatcher de comandos, heartbeat/telemetría, planificador de energía,
                 ejecutor de snapins, auto-actualización firmada, shell remota PTY,
                 trait PlatformOps + MockPlatform.
  platform/      impls de PlatformOps: linux (systemd/nmcli/lspci/smartctl/dpkg…),
                 windows (WMI/NetTCPIP vía PowerShell, registro, SCM); fallback unsupported.
  agent/         el binario `netagent`: CLI, servicio systemd/SCM, watchdog, desinstalación
                 autoprotegida. (9 tests de integración de extremo a extremo)
  mock-netedge/  NetEdge simulado (solo test) que implementa la mitad servidor del protocolo.
```

`core` define `trait PlatformOps`; el binario inyecta `platform::current()` como
`Arc<dyn PlatformOps>`, de modo que `core` nunca depende del código de plataforma y los tests
inyectan un mock.

---

## Identidad, claves y anclas de confianza

Dos direcciones, dos claves — simétrico a NetEdge ⇄ netdd:

- **NetEdge → agente (comandos)** se firman con la **clave de comandos** de NetEdge. El
  agente recibe su mitad pública al darse de alta y la **fija (pin)**; cada comando se
  verifica contra esa clave fijada (espejo del `NETEDGE_PUBLIC_KEY_BYTES` embebido en netdd).
- **agente → NetEdge (informes)** se firman con la **clave propia del agente**, generada en
  el primer arranque y guardada con permisos `0600` en `<data_dir>/agent.key`. NetEdge guarda
  la clave pública de cada agente al alta y puede **revocar un único agente** sin afectar al
  resto.

El canal TLS se verifica mediante **pinning de la clave pública (SPKI)** (`server_spki_pin`),
de modo que un certificado autofirmado de NetEdge es válido sin desactivar la verificación ni
confiar en una CA.

---

## Alta (enrollment)

De un solo uso, arrancada por un `enrollment_token` de corta duración que un administrador
emite para un nodo.

```
agente                                  NetEdge
  | generar par Ed25519 (una vez)         |
  | POST /api/v1/agents/enroll  --------> |  verifica enrollment_token, guarda agent_pubkey
  |   { enrollment_token, agent_pubkey,   |  asigna agent_id
  |     hostname, mac,                    |
  |     machine_fingerprint, os,          |
  |     agent_version }                   |
  | <------------------------------------ |  { agent_id, server_command_pubkey,
  |  persiste state.json (fija la clave)  |    server_spki_pin?, intervalos heartbeat/poll }
```

`machine_fingerprint = hex(sha256(hostname | mac_principal | machine-id))`. El token **nunca**
se reutiliza para autenticar comandos — solo arranca la identidad.

---

## Formatos de mensaje

### Sobre de comando (NetEdge → agente)

```rust
CommandEnvelope {
    version: u8,            // PROTOCOL_VERSION = 1
    command_id: Uuid,
    agent_id: String,       // debe ser igual al id del agente receptor (anti-replay cruzado)
    command: Command,
    issued_at: i64,         // segundos unix
    expires_at: i64,        // segundos unix
    nonce: [u8; 16],
}
SignedCommand { payload: CommandEnvelope, signature: [u8; 64] }
```

La firma es Ed25519 sobre `bincode::serialize(&payload)` — la **misma convención** que el
`SignedLicense` de NetEdge (firmar sobre bincode, firma fija de 64 bytes serializada como
tupla). En el cable, un `SignedCommand` va como JSON dentro de un `ServerMessage` (frame de
texto WS o respuesta de poll); para el token de desinstalación autorizada va como
`base64(bincode(SignedCommand))`.

**Comprobaciones de admisión** (`proto::verify_and_admit`, todas deben pasar; si no, el
comando se rechaza y se reporta como intento):

1. `version == PROTOCOL_VERSION`
2. firma válida contra la clave de comandos **fijada**
3. `agent_id` igual a este agente
4. `issued_at - now ≤ 30s` (desfase de reloj)
5. `now < expires_at`
6. `expires_at - issued_at ≤ 60s` (`MAX_COMMAND_WINDOW_SECS`)
7. `command_id` no visto antes (caché de replay, purgada por expiración)

### Comandos

`Ping` · `Reboot{delay_secs}` · `Shutdown{delay_secs}` · `Exec{program,args,timeout_secs,cwd,env}`
· `SetHostname{name,reboot}` · `SetNetwork(NetworkConfig)` · `GetDrivers` · `GetMissingDrivers`
· `GetSoftwareInventory` · `GetHardware` · `InstallPackage(PackageSpec)` ·
`SchedulePower(PowerSchedule)` · `CancelScheduledPower` · `OpenShell{session_id}` ·
`SelfUpdate{url,version,sha256,binary_sig}` · `Uninstall`.

`SetNetwork` lleva `iface`, `method` (`Dhcp` | `Static{address,prefix,gateway}`), `dns[]`,
`vlan?`. En Linux el agente **detecta el gestor de red activo** (NetworkManager →
systemd-networkd → netplan → ifupdown) y **falla de forma explícita** si no reconoce ninguno —
nunca asume uno por defecto.

### Informes del agente (agente → NetEdge)

```rust
ReportBody<T> { agent_id, issued_at, nonce: [u8;16], inner: T }
SignedReport<T> { body, signature: [u8; 64] }   // Ed25519 sobre bincode(body), clave del agente
```

Variantes de `AgentMessage`: `Hello{agent_id}`, `Ack(SignedReport<CommandAck>)`,
`Result(SignedReport<CommandResult>)`, `Rejected(SignedReport<RejectedCommandReport>)`,
`Heartbeat(SignedReport<Heartbeat>)`, `ShellOutput{session_id,data_b64}`,
`ShellClosed{session_id}`, `Ping`. `CommandResult` lleva `ResultData` para los payloads de
inventario (drivers, drivers ausentes, software, hardware, SMART, informe de red, informe de
instalación).

---

## Transporte

- **WebSocket** (`/api/v1/agents/{id}/ws`) para push casi en tiempo real. Al (re)conectar, el
  agente primero **vacía la cola de comandos por HTTP** y luego atiende los push en vivo.
- **Fallback por polling HTTP** (`GET /api/v1/agents/{id}/commands/poll`) cuando el WS no se
  puede establecer (redes restrictivas/proxies). Los informes salientes van a
  `POST /api/v1/agents/{id}/messages`.
- **Cola de comandos por agente** con estados `queued → sent → acked → failed`. Los comandos
  encolados mientras el agente está offline se entregan al reconectar.
- *Backoff* exponencial entre intentos de conexión.

Todo sobre TLS con pinning SPKI cuando `server_url` es `https`/`wss`.

---

## Telemetría

Un `Heartbeat` firmado y ligero (uptime, último arranque, versión del agente, salud) cada
`heartbeat_interval_secs`, más instantáneas de hardware/SMART bajo demanda. Los nombres de
campo se eligen para alinearse con la ingesta `/api/v1/metrics` + `/api/v1/summary` existente
de NetEdge, de modo que las **mismas reglas de alerta por umbral** (temperatura SMART, sectores
reasignados, salud del disco) apliquen en operación normal, no solo durante el clonado.

---

## Modelo de seguridad (resumen)

- **Identidad Ed25519 por agente** + registro de clave pública al alta → **revocación
  granular**.
- **Cada comando** (incluidos reboot/shutdown/exec) se verifica por firma, está acotado en el
  tiempo y se comprueba contra replay antes de ejecutarse.
- **Los comandos rechazados se auditan como intentos**, nunca se descartan en silencio.
- **Pinning de clave pública TLS** — compatible con autofirmados, nunca «verificación
  desactivada».
- **La ejecución es denegada por defecto**: ningún comando se ejecuta salvo que su programa
  esté en la lista blanca del grupo, y la ejecución arbitraria solo se permite en grupos
  marcados explícitamente como administrativos. Es el valor por defecto documentado, no una
  opción oculta.
- **La auto-actualización está firmada**: se verifican el SHA-256 y la firma Ed25519 del nuevo
  binario (contra la clave de comandos fijada) antes del reemplazo atómico — nunca se ejecuta
  sin verificar.
- **Desinstalación autoprotegida**: quitar el agente requiere un comando `Uninstall` firmado
  por NetEdge (`netagent uninstall --authorized-by <base64>`); parar/matar el proceso
  localmente no lo elimina.

---

## CLI

```
netagent [--config <ruta>] <comando>
  run                 Ejecuta el agente (por defecto). Se da de alta solo si hay token y aún no está enrolado.
  enroll              Da de alta y persiste la identidad.
  install-service     Instala el servicio del SO (unidad systemd / SCM de Windows, watchdog por auto-reinicio).
  uninstall-service   Elimina el servicio del SO.
  uninstall --authorized-by <base64(SignedCommand:Uninstall)>   Auto-desinstalación autorizada.
  version
```

Ruta de config por defecto: `/etc/netagent/agent.toml` (Linux),
`C:\ProgramData\Netagent\agent.toml` (Windows). Ver `config/agent.example.toml`.

- **Linux**: se ejecuta como unidad systemd (`packaging/netagent.service`, `Restart=always`
  = watchdog), con logs al journal. En equipos sin systemd: ejecutar `netagent run` bajo
  cualquier supervisor; el agente es un proceso de primer plano bien educado y recurre a
  syscalls directas para reboot/shutdown/hostname.
- **Windows**: se ejecuta bajo el Service Control Manager (acciones de recuperación por
  auto-reinicio = watchdog).

---

## Contrato del lado servidor (a implementar en NetEdge)

Este repositorio aplaza los cambios reales en NetEdge; el mock prueba el contrato. A
implementar:

**Tablas**

```sql
CREATE TABLE agents (
    id              TEXT PRIMARY KEY,      -- agent_id
    node_id         TEXT,                  -- FK nodes(id); un agente se vincula a un nodo
    pubkey          TEXT NOT NULL,         -- clave pública Ed25519 en hex (verificar informes)
    hostname        TEXT, mac TEXT, machine_fingerprint TEXT,
    agent_version   TEXT, os TEXT,
    status          TEXT NOT NULL DEFAULT 'active',  -- active | revoked
    last_seen       INTEGER,
    enrolled_at     INTEGER NOT NULL
);
CREATE TABLE agent_commands (
    id              TEXT PRIMARY KEY,      -- command_id
    agent_id        TEXT NOT NULL,
    payload         BLOB NOT NULL,         -- bincode(SignedCommand)
    state           TEXT NOT NULL,         -- queued | sent | acked | failed
    issued_by       TEXT,                  -- id de usuario (auditoría)
    created_at      INTEGER NOT NULL,
    result_json     TEXT
);
```

**Endpoints**

| Método | Ruta | Auth | Propósito |
|---|---|---|---|
| POST | `/api/v1/agents/enroll` | token de alta de un solo uso | registra pubkey, devuelve agent_id + clave de comandos a fijar |
| WS | `/api/v1/agents/:id/ws` | Hello firmado por el agente | empuja comandos / recibe informes |
| GET | `/api/v1/agents/:id/commands/poll` | — (la cola es por agente) | vacía los comandos encolados (fallback de polling) |
| POST | `/api/v1/agents/:id/messages` | firma del agente verificada vs pubkey guardada | ingesta de ack/result/rejected/heartbeat |

**Reutilizar los subsistemas existentes de NetEdge** (no reinventar): las primitivas de firma
de `LicenseIssuer`/`license.rs` para la clave de comandos, `audit_log()` para «comando enviado
/ resultado / intento rechazado», `fire_alert()` + `alert_events` para alertas de agente caído
/ fallo de comando / dispositivo sin driver, y las formas de ingesta `/metrics`+`/summary` para
la telemetría. La firma de comandos es el mismo camino Ed25519 «firmar sobre bincode» que las
sub-licencias.

---

## Compilar, probar, ejecutar

```bash
# Compilar todo (Linux). Atajo: ./build.sh
cargo build --workspace --release

# Suite completa de tests (unitarios proto + core + platform + 9 de integración E2E)
cargo test --workspace

# Comprobación de compilación para Windows (sin necesitar un host Windows):
rustup target add x86_64-pc-windows-gnu
cargo check --workspace --target x86_64-pc-windows-gnu

# En Windows, para compilar de forma nativa: build.bat

# Prueba manual de extremo a extremo contra el mock, con el agente + plataforma REALES:
cargo run -p mock-netedge --example serve     # imprime base_url + enrollment_token
#   poner esos valores en /tmp/netagent-agent.toml y luego:
target/release/netagent --config /tmp/netagent-agent.toml run
```

### Cobertura de los tests de integración (`crates/agent/tests/integration.rs`)

1. el alta establece la identidad + fija la clave de comandos
2. un token de alta inválido se rechaza
3. un comando firmado válido se ejecuta y se reporta
4. una **firma inválida** se rechaza y se audita; el comando falsificado nunca se ejecuta
5. un comando **repetido** (mismo `command_id`) se rechaza (se ejecuta exactamente una vez)
6. un comando **caducado** se rechaza
7. los comandos **encolados estando offline** se entregan al conectar
8. el **push por WebSocket** entrega comandos
9. **WS no disponible → fallback a polling HTTP** sigue entregando comandos

La aceptación/rechazo del pin SPKI de TLS está cubierta por tests unitarios en
`core/src/tls.rs`, y la extracción SPKI con certificado real por `proto/src/crypto.rs`.

---

## Estado / advertencias

- Linux: compilado, sin avisos de clippy, totalmente probado (unitarios + integración + una
  ejecución de humo con el binario real).
- Windows: **comprobado en compilación** contra el toolchain `x86_64-pc-windows-gnu` y sin
  avisos de clippy, pero **no ejecutado en este host de desarrollo Linux** — el servicio SCM,
  el inventario de drivers por WMI, la aplicación de NetTCPIP y las rutas de reboot/hostname
  deben validarse en una máquina Windows real.
</content>
</invoke>
