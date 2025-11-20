pub mod config;
pub mod download;
pub mod error;
pub mod telemetry;
pub mod versions;

pub use crate::error::{VersionError, VersionResult};
pub use crate::telemetry::init_tracing;

pub type Result<T> = color_eyre::Result<T>;
