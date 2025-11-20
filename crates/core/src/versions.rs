use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
};

use reqwest::Client;
use serde::Deserialize;
use snafu::ResultExt;

pub const OFFICIAL_MANIFEST_URL: &str =
    "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json";

use tokio::fs;

use crate::{
    download::{DownloadManager, DownloadTask},
    error::*,
};

#[derive(Debug, Clone, Deserialize)]
pub struct VersionManifest {
    pub latest: LatestVersions,
    pub versions: Vec<VersionRef>,
}

#[derive(Debug, Clone)]
pub struct VersionPaths {
    pub versions_dir: PathBuf,
    pub libraries_dir: PathBuf,
    pub assets_dir: PathBuf,
}

impl VersionPaths {
    pub fn from_cache(cache_dir: &Path) -> Self {
        Self {
            versions_dir: cache_dir.join("versions"),
            libraries_dir: cache_dir.join("libraries"),
            assets_dir: cache_dir.join("assets"),
        }
    }

    pub fn client_path(&self, id: &str) -> PathBuf {
        self.versions_dir.join(id).join("client.jar")
    }

    pub fn descriptor_path(&self, id: &str) -> PathBuf {
        self.versions_dir.join(format!("{id}.json"))
    }

    pub fn asset_index_path(&self, id: &str) -> PathBuf {
        self.assets_dir.join("indexes").join(format!("{id}.json"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LatestVersions {
    pub release: String,
    pub snapshot: String,
}

#[derive(Debug, Copy, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VersionKind {
    Release,
    Snapshot,
    OldBeta,
    OldAlpha,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionRef {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: VersionKind,
    pub url: String,
    pub time: String,
    #[serde(rename = "releaseTime")]
    pub release_time: String,
    pub sha1: Option<String>,
    #[serde(default)]
    pub compliance_level: Option<u8>,
}

impl VersionManifest {
    /// Fetch the official version manifest.
    pub async fn fetch(client: &Client) -> VersionResult<Self> {
        let response = client
            .get(OFFICIAL_MANIFEST_URL)
            .send()
            .await
            .context(ReqwestSnafu {
                stage: "manifest.fetch.send",
            })?
            .error_for_status()
            .context(ReqwestSnafu {
                stage: "manifest.fetch.error_check",
            })?;

        let body = response.text().await.context(ReqwestSnafu {
            stage: "manifest.fetch.body",
        })?;

        let manifest: VersionManifest = serde_json::from_str(&body).context(SerializeSnafu {
            stage: "manifest.deserialize",
        })?;

        tracing::info!(
            releases = manifest
                .versions
                .iter()
                .filter(|v| v.kind == VersionKind::Release)
                .count(),
            snapshots = manifest
                .versions
                .iter()
                .filter(|v| v.kind == VersionKind::Snapshot)
                .count(),
            "fetched version manifest"
        );

        Ok(manifest)
    }

    pub fn find_latest_release(&self) -> Option<&VersionRef> {
        self.versions
            .iter()
            .find(|v| v.id == self.latest.release)
            .or_else(|| {
                self.versions
                    .iter()
                    .find(|v| v.kind == VersionKind::Release)
            })
    }

    pub fn find_latest_snapshot(&self) -> Option<&VersionRef> {
        self.versions
            .iter()
            .find(|v| v.id == self.latest.snapshot)
            .or_else(|| {
                self.versions
                    .iter()
                    .find(|v| v.kind == VersionKind::Snapshot)
            })
    }

    pub fn find_version(&self, id: &str) -> Option<&VersionRef> {
        self.versions.iter().find(|v| v.id == id)
    }

    pub fn list_by_kind(&self, kind: VersionKind) -> impl Iterator<Item = &VersionRef> {
        self.versions.iter().filter(move |v| v.kind == kind)
    }

    /// Download the version descriptor JSON for a specific version entry.
    pub async fn download_descriptor(
        &self,
        manager: &DownloadManager,
        version: &VersionRef,
        dest_dir: impl AsRef<Path>,
    ) -> DownloadResult<PathBuf> {
        let task = DownloadTask {
            id: version.id.clone(),
            url: version.url.clone(),
            file_name: Some(format!("{}.json", version.id)),
            sha1: version.sha1.clone(),
            retries: 2,
        };

        let mut outcomes = manager.download(vec![task], dest_dir).await?;
        let outcome = outcomes.pop().ok_or(DownloadError::Generic {
            stage: "download.descriptor.empty",
        })?;

        if let Some(err) = outcome.error {
            return Err(err);
        }

        if let Some(path) = outcome.path {
            return Ok(path);
        }

        Err(DownloadError::Generic {
            stage: "download.descriptor.missing_path",
        })
    }
}

pub fn user_agent() -> Cow<'static, str> {
    Cow::Borrowed("bloom-launcher/0.1")
}

// ---- Detailed version descriptor and resources ----

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionDescriptor {
    pub id: String,
    pub main_class: String,
    pub arguments: Option<Arguments>,
    #[serde(default)]
    pub minecraft_arguments: Option<String>,
    pub asset_index: AssetIndexInfo,
    pub assets: String,
    pub downloads: VersionDownloads,
    pub libraries: Vec<Library>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Arguments {
    #[serde(default)]
    pub game: Vec<ArgumentPart>,
    #[serde(default)]
    pub jvm: Vec<ArgumentPart>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ArgumentPart {
    Plain(String),
    Conditional {
        value: ArgumentValue,
        rules: Option<Vec<Rule>>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ArgumentValue {
    Single(String),
    Multi(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub action: RuleAction,
    #[serde(default)]
    pub os: Option<RuleOs>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Disallow,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleOs {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionDownloads {
    pub client: ArtifactDownload,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactDownload {
    pub url: String,
    pub sha1: Option<String>,
    pub size: Option<u64>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Library {
    pub name: String,
    pub downloads: LibraryDownloads,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LibraryDownloads {
    pub artifact: Option<LibraryArtifact>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LibraryArtifact {
    pub path: String,
    pub url: String,
    pub sha1: Option<String>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetIndexInfo {
    pub id: String,
    pub url: String,
    pub sha1: Option<String>,
    pub size: Option<u64>,
    #[serde(rename = "totalSize")]
    pub total_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetIndex {
    pub objects: HashMap<String, AssetObject>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetObject {
    pub hash: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DownloadedVersion {
    pub client_jar: PathBuf,
    pub libraries: Vec<PathBuf>,
    pub assets_dir: PathBuf,
    pub asset_index_path: PathBuf,
    pub asset_index_id: String,
}

impl VersionDescriptor {
    pub async fn from_file(path: impl AsRef<Path>) -> VersionResult<Self> {
        let bytes = fs::read(path).await.context(DescriptorIoSnafu {
            stage: "version.descriptor.read",
        })?;
        let parsed = serde_json::from_slice(&bytes).context(SerializeSnafu {
            stage: "version.descriptor.parse",
        })?;
        Ok(parsed)
    }

    pub async fn download_all_resources(
        &self,
        manager: &DownloadManager,
        paths: &VersionPaths,
    ) -> DownloadResult<DownloadedVersion> {
        // Client jar
        let client_rel = paths
            .client_path(&self.id)
            .strip_prefix(&paths.versions_dir)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from(format!("{}/client.jar", self.id)));
        let client_task = DownloadTask {
            id: format!("client:{}", self.id),
            url: self.downloads.client.url.clone(),
            file_name: Some(client_rel.to_string_lossy().to_string()),
            sha1: self.downloads.client.sha1.clone(),
            retries: 2,
        };

        // Asset index
        let asset_rel = paths
            .asset_index_path(&self.asset_index.id)
            .strip_prefix(&paths.assets_dir)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from(format!("indexes/{}.json", self.asset_index.id)));
        let asset_index_task = DownloadTask {
            id: format!("asset-index:{}", self.asset_index.id),
            url: self.asset_index.url.clone(),
            file_name: Some(asset_rel.to_string_lossy().to_string()),
            sha1: self.asset_index.sha1.clone(),
            retries: 2,
        };

        // Libraries
        let mut lib_tasks = Vec::new();
        for lib in &self.libraries {
            if let Some(artifact) = &lib.downloads.artifact {
                lib_tasks.push(DownloadTask {
                    id: format!("lib:{}", lib.name),
                    url: artifact.url.clone(),
                    file_name: Some(artifact.path.clone()),
                    sha1: artifact.sha1.clone(),
                    retries: 2,
                });
            }
        }

        let mut libs_paths = Vec::new();
        if !lib_tasks.is_empty() {
            let outcomes = manager.download(lib_tasks, &paths.libraries_dir).await?;
            for outcome in outcomes {
                if let Some(err) = outcome.error {
                    return Err(err);
                }
                let path = outcome.path.ok_or(DownloadError::Generic {
                    stage: "download.lib.missing_path",
                })?;
                libs_paths.push(path);
            }
        }

        let client_outcome = manager
            .download(vec![client_task], &paths.versions_dir)
            .await?
            .pop()
            .ok_or(DownloadError::Generic {
                stage: "download.client.empty",
            })?;
        if let Some(err) = client_outcome.error {
            return Err(err);
        }
        let client_path = client_outcome.path.ok_or(DownloadError::Generic {
            stage: "download.client.missing_path",
        })?;

        let asset_index_outcome = manager
            .download(vec![asset_index_task], &paths.assets_dir)
            .await?
            .pop()
            .ok_or(DownloadError::Generic {
                stage: "download.asset_index.empty",
            })?;
        if let Some(err) = asset_index_outcome.error {
            return Err(err);
        }
        let asset_index_path = asset_index_outcome.path.ok_or(DownloadError::Generic {
            stage: "download.asset_index.missing_path",
        })?;

        // Parse asset index and download assets.
        let asset_tasks = self.build_asset_tasks(&asset_index_path)?;
        let asset_outcomes = manager.download(asset_tasks, &paths.assets_dir).await?;
        for outcome in asset_outcomes {
            if let Some(err) = outcome.error {
                return Err(err);
            }
        }

        Ok(DownloadedVersion {
            client_jar: client_path,
            libraries: libs_paths,
            assets_dir: paths.assets_dir.clone(),
            asset_index_path,
            asset_index_id: self.asset_index.id.clone(),
        })
    }

    fn build_asset_tasks(&self, asset_index_path: &Path) -> DownloadResult<Vec<DownloadTask>> {
        let data = std::fs::read(asset_index_path).context(IoSnafu {
            stage: "assets.index.read",
        })?;
        let index: AssetIndex = serde_json::from_slice(&data).context(SerdeSnafu {
            stage: "assets.index.parse",
        })?;

        let mut tasks = Vec::with_capacity(index.objects.len());
        for (name, obj) in index.objects {
            let prefix = &obj.hash[..2];
            let url = format!(
                "https://resources.download.minecraft.net/{}/{}",
                prefix, obj.hash
            );
            let file_name = format!("objects/{}/{}", prefix, obj.hash);
            tasks.push(DownloadTask {
                id: format!("asset:{name}"),
                url,
                file_name: Some(file_name),
                sha1: Some(obj.hash),
                retries: 2,
            });
        }
        Ok(tasks)
    }

    pub fn build_basic_launch_command(
        &self,
        java_path: impl AsRef<Path>,
        downloaded: &DownloadedVersion,
        instance_dir: &Path,
    ) -> Vec<String> {
        let mut classpath_parts = downloaded.libraries.clone();
        classpath_parts.push(downloaded.client_jar.clone());
        let sep = if cfg!(windows) { ";" } else { ":" };
        let classpath = classpath_parts
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(sep);

        let mut cmd = vec![
            java_path.as_ref().to_string_lossy().to_string(),
            "-cp".into(),
            classpath,
            self.main_class.clone(),
            "--username".into(),
            "Player".into(),
            "--version".into(),
            self.id.clone(),
            "--gameDir".into(),
            instance_dir.to_string_lossy().to_string(),
            "--assetsDir".into(),
            downloaded.assets_dir.to_string_lossy().to_string(),
            "--assetIndex".into(),
            downloaded.asset_index_id.clone(),
            "--accessToken".into(),
            "0".into(),
            "--uuid".into(),
            "00000000-0000-0000-0000-000000000000".into(),
            "--clientId".into(),
            "0".into(),
            "--xuid".into(),
            "0".into(),
            "--userType".into(),
            "msa".into(),
        ];

        // Append basic game/jvm args (without complex rule evaluation).
        if let Some(args) = &self.arguments {
            for part in &args.jvm {
                cmd.extend(self.flatten_argument(part));
            }
            for part in &args.game {
                cmd.extend(self.flatten_argument(part));
            }
        } else if let Some(legacy) = &self.minecraft_arguments {
            cmd.extend(legacy.split_whitespace().map(|s| s.to_string()));
        }

        cmd
    }

    fn flatten_argument(&self, part: &ArgumentPart) -> Vec<String> {
        match part {
            ArgumentPart::Plain(s) => vec![s.clone()],
            ArgumentPart::Conditional { value, rules } => {
                if rules.as_ref().map(|r| Self::rules_allow(r)).unwrap_or(true) {
                    match value {
                        ArgumentValue::Single(s) => vec![s.clone()],
                        ArgumentValue::Multi(list) => list.clone(),
                    }
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn rules_allow(rules: &[Rule]) -> bool {
        // Default allow unless an allow rule matches the OS requirements.
        let mut allowed = true;
        for rule in rules {
            let os_match = rule.os.as_ref().map(Self::os_matches).unwrap_or(true);
            match rule.action {
                RuleAction::Allow => {
                    if os_match {
                        allowed = true;
                    }
                }
                RuleAction::Disallow => {
                    if os_match {
                        allowed = false;
                    }
                }
            }
        }
        allowed
    }

    fn os_matches(os: &RuleOs) -> bool {
        if let Some(name) = &os.name {
            if cfg!(target_os = "windows") {
                name == "windows"
            } else if cfg!(target_os = "macos") {
                name == "osx"
            } else {
                // treat remaining as linux/unix
                name == "linux"
            }
        } else {
            true
        }
    }
}
