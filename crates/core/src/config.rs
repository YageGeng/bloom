use std::path::PathBuf;

use directories::ProjectDirs;

/// Centralized application paths used across the launcher.
#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub instances_dir: PathBuf,
}

impl AppPaths {
    pub fn new() -> color_eyre::Result<Self> {
        // Use vendor/qualifier to avoid clashing with vanilla .minecraft data.
        let dirs = ProjectDirs::from("dev", "Bloom", "BloomLauncher")
            .ok_or_else(|| color_eyre::eyre::eyre!("Unable to resolve platform directories"))?;
        let config_dir = dirs.config_dir().to_path_buf();
        let cache_dir = dirs.cache_dir().to_path_buf();
        let instances_dir = dirs.data_dir().join("instances");

        Ok(Self {
            config_dir,
            cache_dir,
            instances_dir,
        })
    }
}
