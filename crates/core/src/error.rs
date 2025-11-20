use snafu::Snafu;

pub type VersionResult<T> = std::result::Result<T, VersionError>;
pub type DownloadResult<T> = std::result::Result<T, DownloadError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum VersionError {
    #[snafu(display("failed during `{stage}`: {source}"))]
    Reqwest {
        source: reqwest::Error,
        stage: &'static str,
    },
    #[snafu(display("io failed during `{stage}`: {source}"))]
    DescriptorIo {
        source: std::io::Error,
        stage: &'static str,
    },
    #[snafu(display("failed during `{stage}`: {source}"))]
    Serialize {
        source: serde_json::Error,
        stage: &'static str,
    },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum DownloadError {
    #[snafu(display("failed during `{stage}`: {source}"))]
    Http {
        source: reqwest::Error,
        stage: &'static str,
    },
    #[snafu(display("io failed during `{stage}`: {source}"))]
    Io {
        source: std::io::Error,
        stage: &'static str,
    },
    #[snafu(display("url parse failed during `{stage}`: {source}"))]
    Url {
        source: url::ParseError,
        stage: &'static str,
    },
    #[snafu(display("serde failed during `{stage}`: {source}"))]
    Serde {
        source: serde_json::Error,
        stage: &'static str,
    },
    #[snafu(display("cannot determine file name for `{url}`"))]
    Filename { url: String, stage: &'static str },
    #[snafu(display("failed to acquire semaphore during `{stage}`"))]
    Semaphore { stage: &'static str },
    #[snafu(display("unexpected error during `{stage}`"))]
    Generic { stage: &'static str },
    #[snafu(display("hash mismatch during `{stage}` for `{path}`"))]
    HashMismatch { path: String, stage: &'static str },
}
