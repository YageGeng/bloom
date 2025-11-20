use std::path::PathBuf;

pub type Result<T> = color_eyre::Result<T>;

#[derive(Debug, Clone)]
pub struct JvmDiscovery {
    pub java_home: Option<PathBuf>,
    pub detected_binaries: Vec<PathBuf>,
}

impl JvmDiscovery {
    pub fn empty() -> Self {
        Self {
            java_home: None,
            detected_binaries: Vec::new(),
        }
    }
}

pub fn discover_local_jre() -> Result<JvmDiscovery> {
    tracing::info!("JVM module stubbed; detection to be implemented in M4");
    Ok(JvmDiscovery::empty())
}
