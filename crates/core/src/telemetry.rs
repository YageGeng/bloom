use tracing_subscriber::{EnvFilter, fmt};

/// Initialize tracing/logging with env filter support.
pub fn init_tracing() -> color_eyre::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|err| color_eyre::eyre::eyre!("tracing already initialized: {err}"))?;

    Ok(())
}
