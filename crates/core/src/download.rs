use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use futures::StreamExt;
use reqwest::{Client, Url};
use snafu::ResultExt;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    sync::Semaphore,
};
use tracing::{info, warn};

use crate::error::{DownloadError, DownloadResult, HttpSnafu, IoSnafu, UrlSnafu};

#[derive(Debug, Clone)]
pub struct DownloadTask {
    pub id: String,
    pub url: String,
    pub file_name: Option<String>,
    /// Number of additional retry attempts on failure.
    pub retries: u32,
    pub sha1: Option<String>,
}

impl DownloadTask {
    pub fn new(id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            url: url.into(),
            file_name: None,
            retries: 0,
            sha1: None,
        }
    }
}

#[derive(Debug)]
pub struct DownloadOutcome {
    pub id: String,
    pub attempts: u32,
    pub path: Option<PathBuf>,
    pub error: Option<DownloadError>,
}

/// Manages concurrent downloads sharing a semaphore.
#[derive(Clone)]
pub struct DownloadManager {
    client: Client,
    semaphore: Arc<Semaphore>,
    concurrency: usize,
}

impl DownloadManager {
    pub fn new(client: Client, concurrency: usize) -> Self {
        let slots = concurrency.max(1);
        Self {
            client,
            semaphore: Arc::new(Semaphore::new(slots)),
            concurrency: slots,
        }
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Download a list of URLs concurrently into `dest_dir`.
    pub async fn download(
        &self,
        tasks: Vec<DownloadTask>,
        dest_dir: impl AsRef<Path>,
    ) -> DownloadResult<Vec<DownloadOutcome>> {
        self.download_internal(tasks, dest_dir.as_ref()).await
    }

    async fn download_internal(
        &self,
        tasks: Vec<DownloadTask>,
        dest_dir: &Path,
    ) -> DownloadResult<Vec<DownloadOutcome>> {
        fs::create_dir_all(dest_dir).await.context(IoSnafu {
            stage: "download.dest_dir",
        })?;

        let client = self.client.clone();
        let dest_dir = dest_dir.to_path_buf();
        let semaphore = self.semaphore.clone();
        let slots = self.concurrency.max(1);

        let results = futures::stream::iter(tasks.into_iter().map(|task| {
            let client = client.clone();
            let dest_dir = dest_dir.clone();
            let semaphore = semaphore.clone();

            async move {
                let Ok(_permit) = semaphore.acquire_owned().await else {
                    warn!(task = %task.id, "semaphore closed, skipping task");
                    return DownloadOutcome {
                        id: task.id.clone(),
                        attempts: 0,
                        path: None,
                        error: Some(DownloadError::Semaphore {
                            stage: "download.semaphore",
                        }),
                    };
                };

                download_one(&client, task, &dest_dir).await
            }
        }))
        .buffer_unordered(slots)
        .collect::<Vec<_>>()
        .await;

        let mut outcomes = Vec::with_capacity(results.len());
        for result in results {
            outcomes.push(result);
        }

        Ok(outcomes)
    }
}

/// Convenience wrapper when a long-lived manager is not needed by callers.
pub async fn download_files(
    client: &Client,
    tasks: Vec<DownloadTask>,
    dest_dir: impl AsRef<Path>,
    concurrency: usize,
) -> DownloadResult<Vec<DownloadOutcome>> {
    let manager = DownloadManager::new(client.clone(), concurrency);
    manager.download(tasks, dest_dir).await
}

async fn download_one(client: &Client, task: DownloadTask, dest_dir: &Path) -> DownloadOutcome {
    let max_attempts = task.retries.saturating_add(1);
    let mut attempts = 0;

    while attempts < max_attempts {
        attempts += 1;
        info!(task = %task.id, attempt = attempts, "starting download attempt");
        match download_single_attempt(client, &task, dest_dir).await {
            Ok(path) => {
                return DownloadOutcome {
                    id: task.id.clone(),
                    attempts,
                    path: Some(path),
                    error: None,
                };
            }
            Err(err) => {
                warn!(
                    id = %task.id,
                    attempt = attempts,
                    retries = task.retries,
                    error = %err,
                    "download attempt failed"
                );
                if attempts >= max_attempts {
                    return DownloadOutcome {
                        id: task.id.clone(),
                        attempts,
                        path: None,
                        error: Some(err),
                    };
                }
            }
        }
    }

    // Should be unreachable; safeguard just in case.
    DownloadOutcome {
        id: task.id,
        attempts,
        path: None,
        error: Some(DownloadError::Generic {
            stage: "download.unreachable",
        }),
    }
}

async fn download_single_attempt(
    client: &Client,
    task: &DownloadTask,
    dest_dir: &Path,
) -> DownloadResult<PathBuf> {
    let url = Url::parse(&task.url).context(UrlSnafu {
        stage: "download.url.parse",
    })?;

    let file_name = task
        .file_name
        .clone()
        .or_else(|| {
            url.path_segments()
                .and_then(|mut segments| segments.next_back().map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| DownloadError::Filename {
            url: task.url.clone(),
            stage: "download.filename",
        })?;

    let dest_path = dest_dir.join(&file_name);
    if let Some(expected) = &task.sha1
        && dest_path.exists()
        && let Ok(_) = verify_sha1(&dest_path, expected)
    {
        info!(task = %task.id, path = %dest_path.display(), "reusing cached file (sha1 match)");
        return Ok(dest_path);
    }

    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).await.context(IoSnafu {
            stage: "download.create_parent",
        })?;
    }

    let mut response = client
        .get(url)
        .send()
        .await
        .context(HttpSnafu {
            stage: "download.request",
        })?
        .error_for_status()
        .context(HttpSnafu {
            stage: "download.status",
        })?;

    let mut file = File::create(&dest_path).await.context(IoSnafu {
        stage: "download.create_file",
    })?;

    while let Some(chunk) = response.chunk().await.context(HttpSnafu {
        stage: "download.read_chunk",
    })? {
        file.write_all(&chunk).await.context(IoSnafu {
            stage: "download.write_chunk",
        })?;
    }

    file.flush().await.context(IoSnafu {
        stage: "download.flush",
    })?;

    if let Some(expected) = &task.sha1
        && dest_path.exists()
    {
        verify_sha1(&dest_path, expected)?;
        return Ok(dest_path);
    }

    Ok(dest_path)
}

fn verify_sha1(path: &Path, expected: &str) -> DownloadResult<()> {
    use sha1::{Digest, Sha1};

    let mut file = std::fs::File::open(path).context(IoSnafu {
        stage: "download.verify.open",
    })?;
    let mut hasher = Sha1::new();
    std::io::copy(&mut file, &mut hasher).context(IoSnafu {
        stage: "download.verify.read",
    })?;
    let got = hex::encode(hasher.finalize());
    if got != expected {
        return Err(DownloadError::HashMismatch {
            path: path.to_string_lossy().to_string(),
            stage: "download.verify.sha1",
        });
    }
    Ok(())
}
