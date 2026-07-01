//! Netagent core runtime: protocol orchestration, transport, command dispatch,
//! telemetry, scheduling and self-update. OS-agnostic — all host actions go
//! through [`platform::PlatformOps`], injected by the agent binary.

pub mod config;
pub mod dispatcher;
pub mod enroll;
pub mod error;
pub mod heartbeat;
pub mod platform;
pub mod runtime;
pub mod scheduler;
pub mod shell;
pub mod snapin;
pub mod tls;
pub mod transport;
pub mod updater;
pub mod util;

pub use config::{Config, EnrollState, ExecPolicy};
pub use enroll::{enroll, Identity};
pub use error::{CoreError, Result};
pub use platform::{
    Capabilities, DynPlatform, ExecOutput, ExecSpec, PlatformError, PlatformOps, PlatformResult,
};
pub use runtime::{Agent, RuntimeOptions};

#[cfg(any(test, feature = "mock"))]
pub use platform::mock::MockPlatform;
