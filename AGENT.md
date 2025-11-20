---
description:
globs:
alwaysApply: false
---
# 🎨 RUST API DESIGN BEST PRACTICES

> **TL;DR:** Comprehensive API design guidelines for creating ergonomic, maintainable, and idiomatic Rust libraries and services.

## 🔍 API DESIGN STRATEGY

```mermaid
graph TD
    Start["API Design"] --> Purpose{"API<br>Purpose?"}

    Purpose -->|Library| LibAPI["Library API"]
    Purpose -->|Service| ServiceAPI["Service API"]
    Purpose -->|CLI| CLIAPI["CLI API"]

    LibAPI --> Ergonomics["Ergonomic Design"]
    ServiceAPI --> RESTDesign["REST/gRPC Design"]
    CLIAPI --> CLIDesign["Command Interface"]

    Ergonomics --> FlexibleInputs["Flexible Input Types"]
    Ergonomics --> BuilderPattern["Builder Pattern"]
    Ergonomics --> ErrorDesign["Error Design"]

    RESTDesign --> OpenAPI["OpenAPI Documentation"]
    RESTDesign --> Validation["Input Validation"]
    RESTDesign --> Authentication["Authentication"]

    CLIDesign --> Subcommands["Subcommand Structure"]
    CLIDesign --> Configuration["Configuration Management"]
    CLIDesign --> HelpSystem["Help System"]

    FlexibleInputs --> TraitDesign["Trait Design"]
    BuilderPattern --> TraitDesign
    ErrorDesign --> TraitDesign

    OpenAPI --> AsyncAPI["Async API Patterns"]
    Validation --> AsyncAPI
    Authentication --> AsyncAPI

    Subcommands --> Testing["Testing Strategy"]
    Configuration --> Testing
    HelpSystem --> Testing

    TraitDesign --> Documentation["Documentation"]
    AsyncAPI --> Documentation
    Testing --> Documentation

    Documentation --> APIComplete["API Complete"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Ergonomics fill:#4dbb5f,stroke:#36873f,color:white
    style RESTDesign fill:#ffa64d,stroke:#cc7a30,color:white
    style CLIDesign fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 API DESIGN PRINCIPLES

### Ergonomic Function Signatures
```rust
use std::path::Path;

// ✅ Accept flexible input types
pub fn read_config<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    // Implementation
}

// ✅ Use Into for string-like parameters
pub fn create_user<S: Into<String>>(name: S, email: S) -> Result<User, UserError> {
    let name = name.into();
    let email = email.into();
    // Implementation
}

// ✅ Prefer borrowing over ownership when possible
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    // Implementation - doesn't need to own the string
}

// ✅ Return owned data when caller needs ownership
pub fn generate_token() -> String {
    // Implementation returns owned String
}

// ❌ Avoid overly generic signatures without clear benefit
// pub fn process<T, U, F>(input: T, func: F) -> U where F: Fn(T) -> U
```

### Builder Pattern Implementation
```rust
use typed_builder::TypedBuilder;

// ✅ Use TypedBuilder for complex configuration
#[derive(Debug, TypedBuilder)]
pub struct HttpClient {
    #[builder(setter(into))]
    base_url: String,

    #[builder(default = Duration::from_secs(30))]
    timeout: Duration,

    #[builder(default)]
    headers: HashMap<String, String>,

    #[builder(default, setter(strip_option))]
    proxy: Option<String>,

    #[builder(default = false)]
    verify_ssl: bool,
}

impl HttpClient {
    // ✅ Provide a simple constructor for common cases
    pub fn new<S: Into<String>>(base_url: S) -> Self {
        Self::builder()
            .base_url(base_url)
            .build()
    }

    // ✅ Provide convenient factory methods
    pub fn with_auth<S: Into<String>>(base_url: S, token: S) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", token.into()));

        Self::builder()
            .base_url(base_url)
            .headers(headers)
            .build()
    }
}

// ✅ Usage examples
let client = HttpClient::new("https://api.example.com");

let authenticated_client = HttpClient::builder()
    .base_url("https://api.example.com")
    .timeout(Duration::from_secs(60))
    .verify_ssl(true)
    .build();
```

### Error Handling Design
```rust
use thiserror::Error;

// ✅ Well-structured error hierarchy
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Network error: {source}")]
    Network {
        #[from]
        source: reqwest::Error,
    },

    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },

    #[error("Authentication failed")]
    Authentication,

    #[error("Resource not found: {resource_type} with id {id}")]
    NotFound {
        resource_type: String,
        id: String,
    },

    #[error("Rate limit exceeded: retry after {retry_after} seconds")]
    RateLimit { retry_after: u64 },

    #[error("Server error: {status_code}")]
    Server { status_code: u16 },
}

impl ApiError {
    // ✅ Provide utility methods for error classification
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ApiError::Network { .. } | ApiError::RateLimit { .. } | ApiError::Server { status_code } if *status_code >= 500
        )
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ApiError::RateLimit { retry_after } => Some(Duration::from_secs(*retry_after)),
            _ => None,
        }
    }
}

// ✅ Domain-specific result type
pub type ApiResult<T> = Result<T, ApiError>;
```

## 🔄 TRAIT DESIGN PATTERNS

### Cohesive Trait Design
```rust
// ✅ Single responsibility traits
pub trait Serializable {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError>;
    fn deserialize(data: &[u8]) -> Result<Self, SerializationError>
    where
        Self: Sized;
}

pub trait Cacheable {
    type Key;
    fn cache_key(&self) -> Self::Key;
    fn cache_ttl(&self) -> Option<Duration>;
}

// ✅ Composable traits
pub trait Repository<T> {
    type Error;
    type Id;

    async fn find_by_id(&self, id: Self::Id) -> Result<Option<T>, Self::Error>;
    async fn save(&self, entity: &T) -> Result<T, Self::Error>;
    async fn delete(&self, id: Self::Id) -> Result<bool, Self::Error>;
}

pub trait Queryable<T>: Repository<T> {
    type Query;
    type Page;

    async fn find_by_query(&self, query: Self::Query) -> Result<Vec<T>, Self::Error>;
    async fn find_paginated(&self, query: Self::Query, page: Self::Page) -> Result<(Vec<T>, bool), Self::Error>;
}

// ✅ Default implementations for common patterns
pub trait Timestamped {
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;

    // Default implementation for age calculation
    fn age(&self) -> Duration {
        Utc::now().signed_duration_since(self.created_at()).to_std().unwrap_or_default()
    }
}
```

### Extension Traits
```rust
// ✅ Extension traits for external types
pub trait StringExtensions {
    fn is_valid_email(&self) -> bool;
    fn to_snake_case(&self) -> String;
    fn truncate_with_ellipsis(&self, max_len: usize) -> String;
}

impl StringExtensions for str {
    fn is_valid_email(&self) -> bool {
        // Email validation logic
        self.contains('@') && self.contains('.')
    }

    fn to_snake_case(&self) -> String {
        // Snake case conversion
        self.chars()
            .map(|c| if c.is_uppercase() { format!("_{}", c.to_lowercase()) } else { c.to_string() })
            .collect::<String>()
            .trim_start_matches('_')
            .to_string()
    }

    fn truncate_with_ellipsis(&self, max_len: usize) -> String {
        if self.len() <= max_len {
            self.to_string()
        } else {
            format!("{}...", &self[..max_len.saturating_sub(3)])
        }
    }
}

// ✅ Extension traits for Result types
pub trait ResultExtensions<T, E> {
    fn log_error(self) -> Self;
    fn with_context<F>(self, f: F) -> Result<T, ContextError<E>>
    where
        F: FnOnce() -> String;
}

impl<T, E: std::fmt::Debug> ResultExtensions<T, E> for Result<T, E> {
    fn log_error(self) -> Self {
        if let Err(ref e) = self {
            tracing::error!("Operation failed: {:?}", e);
        }
        self
    }

    fn with_context<F>(self, f: F) -> Result<T, ContextError<E>>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| ContextError {
            context: f(),
            source: e,
        })
    }
}
```

## 📦 MODULE ORGANIZATION

### Public API Structure
```rust
// lib.rs - Main library entry point
//! # MyLibrary
//!
//! A comprehensive library for handling X, Y, and Z.
//!
//! ## Quick Start
//!
//! ```rust
//! use my_library::Client;
//!
//! let client = Client::new("api-key");
//! let result = client.fetch_data().await?;
//! ```
//!
//! ## Features
//!
//! - Feature A: Enable with `features = ["feature-a"]`
//! - Feature B: Enable with `features = ["feature-b"]`

// Re-export main public API
pub use client::Client;
pub use config::Config;
pub use error::{Error, Result};

// Re-export important types
pub use types::{User, Product, Order};

// Module declarations
mod client;
mod config;
mod error;
mod types;

// Internal modules (not re-exported)
mod internal {
    pub mod auth;
    pub mod http;
    pub mod serialization;
}

// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{Client, Config, Error, Result};
    pub use crate::types::*;
}

// Feature-gated modules
#[cfg(feature = "async")]
pub mod async_client;

#[cfg(feature = "blocking")]
pub mod blocking_client;
```

### Documentation Standards
```rust
/// A client for interacting with the Example API.
///
/// The `Client` provides methods for authentication, data retrieval,
/// and resource management. It handles rate limiting, retries, and
/// error handling automatically.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// use my_library::Client;
///
/// # tokio_test::block_on(async {
/// let client = Client::new("your-api-key");
/// let users = client.list_users().await?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # });
/// ```
///
/// With custom configuration:
///
/// ```rust
/// use my_library::{Client, Config};
/// use std::time::Duration;
///
/// let config = Config::builder()
///     .timeout(Duration::from_secs(30))
///     .retry_attempts(3)
///     .build();
///
/// let client = Client::with_config("your-api-key", config);
/// ```
pub struct Client {
    api_key: String,
    config: Config,
    http_client: reqwest::Client,
}

impl Client {
    /// Creates a new client with the given API key.
    ///
    /// Uses default configuration with reasonable timeouts and retry settings.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your API key for authentication
    ///
    /// # Examples
    ///
    /// ```rust
    /// use my_library::Client;
    ///
    /// let client = Client::new("sk-1234567890abcdef");
    /// ```
    pub fn new<S: Into<String>>(api_key: S) -> Self {
        Self::with_config(api_key, Config::default())
    }

    /// Creates a new client with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your API key for authentication
    /// * `config` - Custom configuration settings
    ///
    /// # Examples
    ///
    /// ```rust
    /// use my_library::{Client, Config};
    /// use std::time::Duration;
    ///
    /// let config = Config::builder()
    ///     .timeout(Duration::from_secs(60))
    ///     .build();
    ///
    /// let client = Client::with_config("api-key", config);
    /// ```
    pub fn with_config<S: Into<String>>(api_key: S, config: Config) -> Self {
        // Implementation
    }

    /// Retrieves a list of users.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `User` objects on success,
    /// or an `Error` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * The API key is invalid (`Error::Authentication`)
    /// * The request times out (`Error::Network`)
    /// * The server returns an error (`Error::Server`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use my_library::{Client, Error};
    /// # tokio_test::block_on(async {
    /// let client = Client::new("api-key");
    ///
    /// match client.list_users().await {
    ///     Ok(users) => println!("Found {} users", users.len()),
    ///     Err(Error::Authentication) => eprintln!("Invalid API key"),
    ///     Err(e) => eprintln!("Request failed: {}", e),
    /// }
    /// # });
    /// ```
    pub async fn list_users(&self) -> Result<Vec<User>, Error> {
        // Implementation
    }
}
```

## 🔧 CONFIGURATION PATTERNS

### Layered Configuration
```rust
use serde::{Deserialize, Serialize};
use std::path::Path;

// ✅ Configuration with multiple sources
#[derive(Debug, Clone, Serialize, Deserialize, TypedBuilder)]
pub struct Config {
    // Server settings
    #[builder(default = "127.0.0.1".to_string(), setter(into))]
    pub host: String,

    #[builder(default = 8080)]
    pub port: u16,

    // API settings
    #[builder(default = Duration::from_secs(30))]
    pub timeout: Duration,

    #[builder(default = 3)]
    pub retry_attempts: u32,

    // Feature flags
    #[builder(default = true)]
    pub enable_metrics: bool,

    #[builder(default = false)]
    pub debug_mode: bool,
}

impl Config {
    /// Load configuration from multiple sources with precedence:
    /// 1. Environment variables (highest priority)
    /// 2. Configuration file
    /// 3. Defaults (lowest priority)
    pub fn load() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        // Load from file if it exists
        if let Ok(file_config) = Self::from_file("config.toml") {
            config = config.merge(file_config);
        }

        // Override with environment variables
        config = config.merge(Self::from_env()?);

        Ok(config)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(ConfigError::FileRead)?;

        toml::from_str(&content)
            .map_err(ConfigError::ParseError)
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let mut builder = Self::builder();

        if let Ok(host) = std::env::var("HOST") {
            builder = builder.host(host);
        }

        if let Ok(port) = std::env::var("PORT") {
            let port = port.parse()
                .map_err(|_| ConfigError::InvalidPort)?;
            builder = builder.port(port);
        }

        if let Ok(timeout) = std::env::var("TIMEOUT_SECONDS") {
            let seconds = timeout.parse()
                .map_err(|_| ConfigError::InvalidTimeout)?;
            builder = builder.timeout(Duration::from_secs(seconds));
        }

        Ok(builder.build())
    }

    fn merge(self, other: Self) -> Self {
        // Merge logic - other takes precedence
        Self {
            host: if other.host != "127.0.0.1" { other.host } else { self.host },
            port: if other.port != 8080 { other.port } else { self.port },
            timeout: if other.timeout != Duration::from_secs(30) { other.timeout } else { self.timeout },
            retry_attempts: if other.retry_attempts != 3 { other.retry_attempts } else { self.retry_attempts },
            enable_metrics: other.enable_metrics, // Boolean fields always take the other value
            debug_mode: other.debug_mode,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::builder().build()
    }
}
```

## 🎭 ASYNC API PATTERNS

### Async Iterator and Stream Design
```rust
use futures::Stream;
use std::pin::Pin;

// ✅ Async iterator for paginated results
pub struct PaginatedStream<T> {
    client: Arc<Client>,
    query: Query,
    current_page: Option<String>,
    buffer: VecDeque<T>,
    exhausted: bool,
}

impl<T> PaginatedStream<T> {
    pub fn new(client: Arc<Client>, query: Query) -> Self {
        Self {
            client,
            query,
            current_page: None,
            buffer: VecDeque::new(),
            exhausted: false,
        }
    }
}

impl<T: Unpin> Stream for PaginatedStream<T>
where
    T: for<'de> Deserialize<'de> + Send + 'static,
{
    type Item = Result<T, ApiError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(item) = self.buffer.pop_front() {
            return Poll::Ready(Some(Ok(item)));
        }

        if self.exhausted {
            return Poll::Ready(None);
        }

        // Fetch next page
        let client = self.client.clone();
        let query = self.query.clone();
        let page = self.current_page.clone();

        let future = async move {
            client.fetch_page(query, page).await
        };

        // Poll the future and handle the result
        // Implementation depends on your async runtime
        todo!("Implement polling logic")
    }
}

// ✅ Cancellation-aware async operations
pub struct CancellableOperation<T> {
    inner: Pin<Box<dyn Future<Output = Result<T, ApiError>> + Send>>,
    cancel_token: CancelToken,
}

impl<T> CancellableOperation<T> {
    pub fn new<F>(future: F, cancel_token: CancelToken) -> Self
    where
        F: Future<Output = Result<T, ApiError>> + Send + 'static,
    {
        Self {
            inner: Box::pin(future),
            cancel_token,
        }
    }
}

impl<T> Future for CancellableOperation<T> {
    type Output = Result<T, ApiError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cancel_token.is_cancelled() {
            return Poll::Ready(Err(ApiError::Cancelled));
        }

        self.inner.as_mut().poll(cx)
    }
}
```

## 🔍 TESTING API DESIGN

### Testable API Structure
```rust
// ✅ Dependency injection for testability
pub trait HttpClientTrait: Send + Sync {
    async fn get(&self, url: &str) -> Result<Response, HttpError>;
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, HttpError>;
}

pub struct Client<H: HttpClientTrait> {
    http_client: H,
    config: Config,
}

impl<H: HttpClientTrait> Client<H> {
    pub fn new(http_client: H, config: Config) -> Self {
        Self { http_client, config }
    }

    pub async fn fetch_user(&self, id: &str) -> Result<User, ApiError> {
        let url = format!("{}/users/{}", self.config.base_url, id);
        let response = self.http_client.get(&url).await?;
        // Parse response
        todo!()
    }
}

// ✅ Production implementation
impl HttpClientTrait for reqwest::Client {
    async fn get(&self, url: &str) -> Result<Response, HttpError> {
        // Implementation
    }

    async fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, HttpError> {
        // Implementation
    }
}

// ✅ Mock implementation for testing
#[cfg(test)]
pub struct MockHttpClient {
    responses: HashMap<String, Result<Response, HttpError>>,
}

#[cfg(test)]
impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
        }
    }

    pub fn expect_get(&mut self, url: &str, response: Result<Response, HttpError>) {
        self.responses.insert(format!("GET {}", url), response);
    }
}

#[cfg(test)]
impl HttpClientTrait for MockHttpClient {
    async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.responses
            .get(&format!("GET {}", url))
            .cloned()
            .unwrap_or(Err(HttpError::NotFound))
    }

    async fn post(&self, url: &str, _body: Vec<u8>) -> Result<Response, HttpError> {
        self.responses
            .get(&format!("POST {}", url))
            .cloned()
            .unwrap_or(Err(HttpError::NotFound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_user_success() {
        let mut mock_client = MockHttpClient::new();
        mock_client.expect_get(
            "https://api.example.com/users/123",
            Ok(Response {
                status: 200,
                body: r#"{"id": "123", "name": "John"}"#.to_string(),
            }),
        );

        let client = Client::new(mock_client, Config::default());
        let user = client.fetch_user("123").await.unwrap();

        assert_eq!(user.id, "123");
        assert_eq!(user.name, "John");
    }
}
```

## ✅ API DESIGN CHECKLIST

```markdown
### API Design Implementation Verification
- [ ] Function signatures accept flexible input types (AsRef, Into)
- [ ] Error types are well-structured with proper context
- [ ] Builder pattern used for complex configuration
- [ ] Traits have single responsibility and clear contracts
- [ ] Public API is well-documented with examples
- [ ] Configuration supports multiple sources with precedence
- [ ] Async APIs handle cancellation and backpressure
- [ ] Dependencies are injected for testability
- [ ] Extension traits enhance existing types ergonomically
- [ ] Module organization follows convention
- [ ] Feature gates are used appropriately
- [ ] Error handling provides actionable information
- [ ] API follows Rust naming conventions
- [ ] Generic parameters have appropriate bounds
- [ ] Public API surface is minimal but complete
```

This API design guide ensures consistent, ergonomic, and maintainable interfaces across Rust projects.
---
description:
globs:
alwaysApply: false
---
# 🦀 RUST CORE CODE QUALITY STANDARDS

> **TL;DR:** Essential code quality rules for all Rust projects, focusing on maintainable, production-ready code that follows modern Rust 2024 idioms.

## 🔍 CODE QUALITY STRATEGY SELECTION

```mermaid
graph TD
    Start["Code Quality Requirements"] --> ProjectType{"Project Type?"}

    ProjectType -->|"Simple Library"| SimpleLib["Simple Library Rules"]
    ProjectType -->|"Complex Application"| ComplexApp["Complex Application Rules"]
    ProjectType -->|"CLI Tool"| CLITool["CLI Tool Rules"]
    ProjectType -->|"Web Service"| WebService["Web Service Rules"]

    SimpleLib --> BasicRules["Basic Quality Rules"]
    ComplexApp --> AdvancedRules["Advanced Quality Rules"]
    CLITool --> BasicRules
    WebService --> AdvancedRules

    BasicRules --> Naming["Naming Strategy"]
    AdvancedRules --> Naming

    Naming --> NamingRules["• Functionality-based files<br>• Descriptive specific names<br>• No implementation suffixes"]

    NamingRules --> Structure["Code Structure"]

    Structure --> StructureRules["• File-based organization<br>• Size limitations (500 lines)<br>• Single responsibility<br>• Function size (150 lines)"]

    StructureRules --> Safety["Safety Requirements"]

    Safety --> SafetyRules["• Rust 2024 edition<br>• No unsafe code<br>• No unwrap() in production<br>• Proper error handling"]

    SafetyRules --> Testing["Testing Strategy"]

    Testing --> TestingRules["• Unit tests same file<br>• Integration tests separate<br>• Doc tests with examples"]

    TestingRules --> Verification["Quality Verification"]

    Verification --> Build["cargo build"]
    Verification --> Test["cargo test"]
    Verification --> Clippy["cargo clippy"]

    Build --> AllPass{"All Pass?"}
    Test --> AllPass
    Clippy --> AllPass

    AllPass -->|"Yes"| Success["✅ Quality Standards Met"]
    AllPass -->|"No"| FixIssues["🔧 Fix Issues"]

    FixIssues --> Verification

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style ProjectType fill:#ffa64d,stroke:#cc7a30,color:white
    style SimpleLib fill:#4dbb5f,stroke:#36873f,color:white
    style ComplexApp fill:#d94dbb,stroke:#a3378a,color:white
    style CLITool fill:#9f4dbb,stroke:#7a3787,color:white
    style WebService fill:#bb4d4d,stroke:#873636,color:white
    style BasicRules fill:#bbbb4d,stroke:#878736,color:white
    style AdvancedRules fill:#4dbbbb,stroke:#368787,color:white
    style Success fill:#5fbb5f,stroke:#4a8f4a,color:white
    style FixIssues fill:#ff6b6b,stroke:#cc5555,color:white
```

## 🎯 FUNDAMENTAL PRINCIPLES

### Code Organization
- **Functionality-based files**: Use meaningful file names like `user.rs`, `product.rs`, `auth.rs` instead of generic `models.rs`, `traits.rs`, `types.rs`
- **Meaningful naming**: Avoid names like `UserServiceImpl` - use descriptive, specific names
- **File size limits**: Maximum 500 lines per file (excluding tests)
- **Function size**: Maximum 150 lines per function
- **Single Responsibility**: Each module should have one clear purpose

### Rust Edition and Safety
- **Always use Rust 2024 edition**
- **Never use `unsafe` code** - find safe alternatives
- **Production-ready code**: All code must be deployable and maintainable
- **No `unwrap()` or `expect()`** in production code - use proper error handling

## 🏗️ CODE STRUCTURE PATTERNS

### Data Structure Organization
```rust
// ✅ Good: Functionality-based organization
// src/user.rs - All user-related types and logic
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]  // Always use camelCase for JSON serialization
pub struct User {
    pub user_id: String,
    pub display_name: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

// ✅ Good: Meaningful trait names
pub trait UserValidator {
    fn validate(&self, user: &User) -> Result<(), ValidationError>;
}

// ❌ Bad: Generic file organization
// src/models.rs, src/traits.rs, src/types.rs
// ❌ Bad: Poor naming
// struct UserValidatorImpl
```

### Serde Configuration
```rust
// ✅ Always use camelCase for JSON serialization
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse {
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

// This serializes to:
// {"userId": "...", "createdAt": "...", "isActive": true}
```

## 🔧 BUILD AND QUALITY CHECKS

### Mandatory Verification Steps
After completing any code changes, **always run in order**:

```bash
# 1. Build check
cargo build

# 2. Test execution
cargo test

# 3. Linting
cargo clippy

# All must pass before considering code complete
```

### Clippy Configuration
```toml
# Cargo.toml
[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
unwrap_used = "deny"
expect_used = "deny"
```

## 🗂️ FILE NAMING CONVENTIONS

### Module Organization Patterns
```rust
// ✅ Good: Feature-based modules
src/
├── user/
│   ├── mod.rs
│   ├── service.rs       // UserService logic
│   ├── repository.rs    // User data access
│   └── validator.rs     // User validation
├── product/
│   ├── mod.rs
│   ├── catalog.rs       // Product catalog logic
│   └── pricing.rs       // Product pricing logic
└── auth/
    ├── mod.rs
    ├── token.rs         // Token management
    └── session.rs       // Session handling
```

### Naming Best Practices
```rust
// ✅ Good naming examples
pub struct UserService;                // Clear, specific
pub struct ProductCatalog;             // Action-oriented
pub struct DatabaseConnection;         // Descriptive

// ❌ Bad naming examples
pub struct UserServiceImpl;            // Unnecessary "Impl" suffix
pub struct Helper;                     // Too generic
pub struct Manager;                    // Vague responsibility
```

## 🧪 TESTING STANDARDS

### Unit Test Placement
```rust
// ✅ Always place unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_validation() {
        let validator = UserValidator::new();
        let user = User::default();
        assert!(validator.validate(&user).is_ok());
    }
}

// ❌ Don't create separate test files for unit tests
// tests/user_test.rs (this is for integration tests only)
```

### Test Naming
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email_passes_validation() {
        // Test name clearly describes the scenario
    }

    #[test]
    fn test_empty_email_returns_error() {
        // Specific about what's being tested
    }
}
```

## 📝 DOCUMENTATION STANDARDS

### Code Documentation
```rust
/// Validates user data according to business rules.
///
/// # Examples
///
/// ```rust
/// let validator = UserValidator::new();
/// let user = User::builder()
///     .email("user@example.com")
///     .display_name("John Doe")
///     .build();
///
/// assert!(validator.validate(&user).is_ok());
/// ```
///
/// # Errors
///
/// Returns `ValidationError` if:
/// - Email is empty or invalid format
/// - Display name is too long
/// - Required fields are missing
pub struct UserValidator {
    rules: Vec<ValidationRule>,
}
```

## 🚨 ANTI-PATTERNS TO AVOID

### Code Organization Anti-Patterns
```rust
// ❌ Don't use generic file names
// src/models.rs - mixing unrelated types
// src/utils.rs - catch-all for random functions
// src/helpers.rs - unclear responsibility

// ❌ Don't use implementation suffixes
pub struct UserValidatorImpl;
pub struct DatabaseManagerImpl;

// ❌ Don't mix concerns in single files
// src/app.rs containing database, validation, and HTTP logic

// ❌ Don't use overly long files
// Any file > 500 lines (excluding tests) needs refactoring
```

## ✅ QUALITY CHECKLIST

```markdown
### Code Quality Verification
- [ ] Uses Rust 2024 edition
- [ ] No `unsafe` code blocks
- [ ] No `unwrap()` or `expect()` in production code
- [ ] All data structures use `#[serde(rename_all = "camelCase")]`
- [ ] Files organized by functionality, not type
- [ ] Meaningful names (no "Impl" suffixes)
- [ ] Functions ≤ 150 lines
- [ ] Files ≤ 500 lines (excluding tests)
- [ ] Unit tests in same file as implementation
- [ ] `cargo build` passes
- [ ] `cargo test` passes
- [ ] `cargo clippy` passes with no warnings
- [ ] Public APIs documented with examples
```

This code quality standard ensures consistent, maintainable, and production-ready Rust code across all projects.
---
description:
globs:
alwaysApply: false
---
# 📦 RUST DEPENDENCY MANAGEMENT

> **TL;DR:** Centralized dependency management guidelines for consistent, secure, and maintainable Rust projects.

## 🔍 DEPENDENCY MANAGEMENT STRATEGY

```mermaid
graph TD
    Start["Project Setup"] --> WorkspaceCheck{"Workspace<br>Project?"}

    WorkspaceCheck -->|Yes| WorkspaceRoot["Use Workspace Dependencies"]
    WorkspaceCheck -->|No| SingleCrate["Single Crate Dependencies"]

    WorkspaceRoot --> WorkspaceTable["[workspace.dependencies]<br>Define versions centrally"]
    SingleCrate --> DirectDeps["[dependencies]<br>Direct version specification"]

    WorkspaceTable --> CrateUsage["[dependencies]<br>crate = { workspace = true }"]

    CrateUsage --> SecurityCheck["Security Assessment"]
    DirectDeps --> SecurityCheck

    SecurityCheck --> Audit["cargo audit"]
    Audit --> Outdated["cargo outdated"]
    Outdated --> VersionPin["Pin Critical Versions"]

    VersionPin --> FeatureGates["Feature Gate Optional Deps"]
    FeatureGates --> Testing["Testing Dependencies"]
    Testing --> Documentation["Document Choices"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style WorkspaceRoot fill:#4dbb5f,stroke:#36873f,color:white
    style SingleCrate fill:#ffa64d,stroke:#cc7a30,color:white
    style SecurityCheck fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 DEPENDENCY STRATEGY

### Workspace Dependencies Priority
```toml
# Always prefer workspace dependencies first
[dependencies]
tokio = { workspace = true }
serde = { workspace = true, features = ["derive"] }

# Only add new dependencies if not available in workspace
# Request permission before modifying Cargo.toml
```

## 📋 STANDARD CRATE RECOMMENDATIONS

### Core Utilities
```toml
# Error handling
anyhow = "1.0"                               # Simple error handling
thiserror = "2.0"                           # Structured error types
derive_more = { version = "2", features = ["full"] }  # Extended derive macros

# Data structures
typed-builder = "0.21"                      # Builder pattern
uuid = { version = "1.17", features = ["v4", "v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
time = { version = "0.3", features = ["serde"] }
```

### Async/Concurrency
```toml
tokio = { version = "1.45", features = [
    "macros",
    "rt-multi-thread",
    "signal",
    "sync",
    "fs",
    "net",
    "time"
] }
async-trait = "0.1"                         # Async traits
futures = "0.3"                             # Async utilities
dashmap = { version = "6", features = ["serde"] }  # Concurrent HashMap
```

### Serialization
```toml
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
base64 = "0.22"
```

### Web/HTTP
```toml
axum = { version = "0.8", features = ["macros", "http2", "multipart"] }
reqwest = { version = "0.12", default-features = false, features = [
    "charset",
    "rustls-tls-webpki-roots",
    "http2",
    "json",
    "cookies",
    "gzip",
    "brotli",
    "zstd",
    "deflate"
] }
tower = { version = "0.5", features = ["util", "timeout", "load-shed"] }
tower-http = { version = "0.6", features = ["cors", "trace", "compression"] }
http = "1.0"
```

### Database
```toml
sqlx = { version = "0.8", features = [
    "chrono",
    "postgres",
    "runtime-tokio-rustls",
    "sqlite",
    "time",
    "uuid",
    "json"
] }
```

### Documentation/API
```toml
utoipa = { version = "5", features = ["axum_extras", "chrono", "uuid"] }
utoipa-axum = "0.2"
utoipa-swagger-ui = { version = "9", features = [
    "axum",
    "vendored"
], default-features = false }
schemars = { version = "0.8", features = ["chrono", "url"] }
```

### CLI Applications
```toml
clap = { version = "4.0", features = ["derive", "env", "unicode"] }
dialoguer = "0.11"                          # Interactive prompts
indicatif = "0.17"                          # Progress bars
colored = "2.0"                             # Terminal colors
console = "0.15"                            # Terminal utilities
```

### Configuration Management
```toml
figment = { version = "0.10", features = ["yaml", "toml", "env"] }
notify = "6.0"                              # File watching
arc-swap = "1.0"                            # Atomic configuration updates
validator = { version = "0.18", features = ["derive"] }
```

### Observability
```toml
prometheus = "0.13"                         # Metrics collection
opentelemetry = "0.23"                      # Distributed tracing
tracing-opentelemetry = "0.23"              # Tracing integration
dashmap = "6.0"                             # Lock-free concurrent maps
```

### Frontend Integration
```toml
rust-embed = "8.0"                          # Static asset embedding
mime_guess = "2.0"                          # MIME type detection
```

### gRPC/Protobuf
```toml
tonic = { version = "0.13", features = ["transport", "codegen", "prost"] }
prost = "0.13"
prost-types = "0.13"
tonic-build = "0.13"
prost-build = "0.13"
tonic-health = "0.13"
tonic-reflection = "0.13"
```

### Development/Testing
```toml
[dev-dependencies]
tempfile = "3.0"                            # Temporary files
wiremock = "0.6"                            # HTTP mocking
assert_cmd = "2.0"                          # CLI testing
predicates = "3.0"                          # Test assertions
axum-test = "15.0"                          # Axum testing
tokio-test = "0.4"                          # Tokio testing utilities
temp-env = "0.3"                            # Environment variable testing
```

## 🔧 FEATURE FLAG STRATEGY

### Minimal Feature Sets
```toml
# ✅ Good: Only enable needed features
reqwest = { version = "0.12", default-features = false, features = [
    "rustls-tls-webpki-roots",  # TLS support
    "json",                     # JSON serialization
    "gzip"                      # Compression
] }

# ❌ Bad: Enabling all features
# reqwest = { version = "0.12", features = ["full"] }
```

### Feature Documentation
```toml
# Document why each feature is needed
tokio = { version = "1.45", features = [
    "macros",          # #[tokio::main] and #[tokio::test]
    "rt-multi-thread", # Multi-threaded runtime
    "signal",          # Signal handling for graceful shutdown
    "net",             # Network primitives
    "fs",              # File system operations
    "time"             # Time utilities
] }
```

## 🔒 SECURITY CONSIDERATIONS

### TLS Configuration
```toml
# ✅ Prefer rustls over openssl
reqwest = { version = "0.12", default-features = false, features = [
    "rustls-tls-webpki-roots"  # Use rustls with web PKI roots
] }

# ❌ Avoid native-tls when possible
# reqwest = { version = "0.12", features = ["native-tls"] }
```

### Crypto Dependencies
```toml
# Use well-established crypto crates
rand = { version = "0.8", features = ["std_rng"] }
getrandom = { version = "0.3", features = ["std"] }
jsonwebtoken = "9.0"
argon2 = "0.15"
```

## 📊 VERSION STRATEGY

### Version Selection Rules
1. **Always use latest stable versions** for new dependencies
2. **Use semantic versioning** - prefer `"1.0"` over `"=1.0.0"`
3. **Check workspace first** - never duplicate dependencies
4. **Document breaking changes** when updating major versions

### Workspace Version Management
```toml
# workspace Cargo.toml
[workspace.dependencies]
tokio = { version = "1.45", features = ["macros", "rt-multi-thread"] }
serde = { version = "1.0", features = ["derive"] }
anyhow = "1.0"
thiserror = "2.0"
uuid = { version = "1.17", features = ["v4", "serde"] }

# Individual crate Cargo.toml
[dependencies]
tokio = { workspace = true, features = ["signal"] }  # Add extra features as needed
serde = { workspace = true }
anyhow = { workspace = true }
```

## 🚨 DEPENDENCY ANTI-PATTERNS

### What to Avoid
```toml
# ❌ Don't duplicate workspace dependencies
[dependencies]
tokio = "1.0"  # Already in workspace

# ❌ Don't enable unnecessary features
tokio = { version = "1.45", features = ["full"] }  # Too broad

# ❌ Don't use outdated versions
serde = "0.9"  # Use latest stable

# ❌ Don't mix TLS implementations
reqwest = { version = "0.12", features = ["native-tls", "rustls-tls"] }

# ❌ Don't use git dependencies in production
my-crate = { git = "https://github.com/user/repo" }
```

### Common Mistakes
```rust
// ❌ Don't import with wildcard
use serde::*;

// ✅ Import specific items
use serde::{Deserialize, Serialize};

// ❌ Don't use deprecated APIs
use std::sync::ONCE_INIT;  // Deprecated

// ✅ Use modern alternatives
use std::sync::Once;
```

## 📝 DEPENDENCY AUDIT

### Regular Maintenance
```bash
# Check for outdated dependencies
cargo outdated

# Audit for security vulnerabilities
cargo audit

# Check for unused dependencies
cargo machete

# Update dependencies
cargo update
```

### Security Best Practices
```toml
# Pin security-critical dependencies
openssl = "=0.10.64"  # Pin exact version for security

# Use cargo-deny for policy enforcement
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
```

## ✅ DEPENDENCY CHECKLIST

```markdown
### Dependency Management Verification
- [ ] Uses workspace dependencies when available
- [ ] Features flags are minimal and documented
- [ ] Prefers rustls over native-tls
- [ ] Uses latest stable versions
- [ ] Security-critical deps are audited
- [ ] No duplicate dependencies across workspace
- [ ] Dev dependencies separated from runtime deps
- [ ] Feature documentation explains necessity
- [ ] Regular dependency updates scheduled
- [ ] Vulnerability scanning enabled
```

This dependency management guide ensures consistent, secure, and maintainable dependency choices across all Rust projects.
---
description:
globs:
alwaysApply: false
---
# 🎭 RUST DESIGN PATTERNS

> **TL;DR:** Essential design patterns for Rust applications, focusing on idiomatic solutions that leverage Rust's ownership system and zero-cost abstractions.

## 🔍 DESIGN PATTERN SELECTION STRATEGY

```mermaid
graph TD
    Start["Design Challenge"] --> ProblemType{"Problem<br>Category?"}

    ProblemType -->|Object Creation| Creational["Creational Patterns"]
    ProblemType -->|Object Behavior| Behavioral["Behavioral Patterns"]
    ProblemType -->|Object Structure| Structural["Structural Patterns"]
    ProblemType -->|Concurrency| ConcurrencyP["Concurrency Patterns"]

    Creational --> BuilderCheck{"Complex<br>Configuration?"}
    Creational --> FactoryCheck{"Multiple<br>Implementations?"}

    BuilderCheck -->|Yes| TypeStateBuilder["Type-State Builder"]
    FactoryCheck -->|Yes| AbstractFactory["Abstract Factory"]

    Behavioral --> StrategyCheck{"Runtime Algorithm<br>Selection?"}
    Behavioral --> CommandCheck{"Undo/Redo<br>Required?"}
    Behavioral --> ObserverCheck{"Event-Driven<br>Architecture?"}

    StrategyCheck -->|Yes| StrategyPattern["Strategy Pattern"]
    CommandCheck -->|Yes| CommandPattern["Command Pattern"]
    ObserverCheck -->|Yes| ObserverPattern["Observer Pattern"]

    Structural --> AdapterCheck{"External API<br>Integration?"}
    Structural --> DecoratorCheck{"Cross-Cutting<br>Concerns?"}

    AdapterCheck -->|Yes| AdapterPattern["Adapter Pattern"]
    DecoratorCheck -->|Yes| DecoratorPattern["Decorator Pattern"]

    ConcurrencyP --> ActorCheck{"Isolated State<br>Management?"}
    ConcurrencyP --> PipelineCheck{"Data Pipeline<br>Processing?"}

    ActorCheck -->|Yes| ActorPattern["Actor Pattern"]
    PipelineCheck -->|Yes| PipelinePattern["Pipeline Pattern"]

    TypeStateBuilder --> Implementation["Implementation"]
    AbstractFactory --> Implementation
    StrategyPattern --> Implementation
    CommandPattern --> Implementation
    ObserverPattern --> Implementation
    AdapterPattern --> Implementation
    DecoratorPattern --> Implementation
    ActorPattern --> Implementation
    PipelinePattern --> Implementation

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Creational fill:#4dbb5f,stroke:#36873f,color:white
    style Behavioral fill:#ffa64d,stroke:#cc7a30,color:white
    style Structural fill:#d94dbb,stroke:#a3378a,color:white
    style ConcurrencyP fill:#9d4dbb,stroke:#7a3a8a,color:white
```

## 🏗️ CREATIONAL PATTERNS

### Builder Pattern with Type State
```rust
use std::marker::PhantomData;

// ✅ Type-safe builder preventing invalid configurations
pub struct DatabaseConfigBuilder<HasHost, HasPort, HasDatabase> {
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
    username: Option<String>,
    password: Option<String>,
    _marker: PhantomData<(HasHost, HasPort, HasDatabase)>,
}

pub struct Missing;
pub struct Present;

impl DatabaseConfigBuilder<Missing, Missing, Missing> {
    pub fn new() -> Self {
        Self {
            host: None,
            port: None,
            database: None,
            username: None,
            password: None,
            _marker: PhantomData,
        }
    }
}

impl<HasPort, HasDatabase> DatabaseConfigBuilder<Missing, HasPort, HasDatabase> {
    pub fn host(self, host: impl Into<String>) -> DatabaseConfigBuilder<Present, HasPort, HasDatabase> {
        DatabaseConfigBuilder {
            host: Some(host.into()),
            port: self.port,
            database: self.database,
            username: self.username,
            password: self.password,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasDatabase> DatabaseConfigBuilder<HasHost, Missing, HasDatabase> {
    pub fn port(self, port: u16) -> DatabaseConfigBuilder<HasHost, Present, HasDatabase> {
        DatabaseConfigBuilder {
            host: self.host,
            port: Some(port),
            database: self.database,
            username: self.username,
            password: self.password,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasPort> DatabaseConfigBuilder<HasHost, HasPort, Missing> {
    pub fn database(self, database: impl Into<String>) -> DatabaseConfigBuilder<HasHost, HasPort, Present> {
        DatabaseConfigBuilder {
            host: self.host,
            port: self.port,
            database: Some(database.into()),
            username: self.username,
            password: self.password,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasPort, HasDatabase> DatabaseConfigBuilder<HasHost, HasPort, HasDatabase> {
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }
}

// Only allow building when all required fields are present
impl DatabaseConfigBuilder<Present, Present, Present> {
    pub fn build(self) -> DatabaseConfig {
        DatabaseConfig {
            host: self.host.unwrap(),
            port: self.port.unwrap(),
            database: self.database.unwrap(),
            username: self.username,
            password: self.password,
        }
    }
}

// ✅ Usage - compiler enforces required fields
let config = DatabaseConfigBuilder::new()
    .host("localhost")
    .port(5432)
    .database("myapp")
    .username("admin")
    .build();
```

### Factory Pattern with Associated Types
```rust
// ✅ Factory pattern for creating different database connections
pub trait ConnectionFactory {
    type Connection;
    type Config;
    type Error;

    fn create_connection(config: Self::Config) -> Result<Self::Connection, Self::Error>;
    fn connection_type() -> &'static str;
}

pub struct PostgresFactory;
pub struct SqliteFactory;

impl ConnectionFactory for PostgresFactory {
    type Connection = sqlx::PgPool;
    type Config = PostgresConfig;
    type Error = sqlx::Error;

    fn create_connection(config: Self::Config) -> Result<Self::Connection, Self::Error> {
        // Implementation
    }

    fn connection_type() -> &'static str {
        "PostgreSQL"
    }
}

impl ConnectionFactory for SqliteFactory {
    type Connection = sqlx::SqlitePool;
    type Config = SqliteConfig;
    type Error = sqlx::Error;

    fn create_connection(config: Self::Config) -> Result<Self::Connection, Self::Error> {
        // Implementation
    }

    fn connection_type() -> &'static str {
        "SQLite"
    }
}

// ✅ Generic database service using factory
pub struct DatabaseService<F: ConnectionFactory> {
    connection: F::Connection,
    _factory: PhantomData<F>,
}

impl<F: ConnectionFactory> DatabaseService<F> {
    pub fn new(config: F::Config) -> Result<Self, F::Error> {
        let connection = F::create_connection(config)?;
        Ok(Self {
            connection,
            _factory: PhantomData,
        })
    }

    pub fn connection_info(&self) -> &'static str {
        F::connection_type()
    }
}
```

## 🔄 BEHAVIORAL PATTERNS

### Strategy Pattern with Enums
```rust
// ✅ Strategy pattern for different authentication methods
#[derive(Debug, Clone)]
pub enum AuthStrategy {
    Bearer { token: String },
    ApiKey { key: String, header: String },
    Basic { username: String, password: String },
    OAuth2 { client_id: String, client_secret: String },
}

impl AuthStrategy {
    pub fn apply_to_request(&self, request: &mut Request) -> Result<(), AuthError> {
        match self {
            AuthStrategy::Bearer { token } => {
                request.headers_mut().insert(
                    "Authorization",
                    format!("Bearer {}", token).parse().unwrap(),
                );
            }
            AuthStrategy::ApiKey { key, header } => {
                request.headers_mut().insert(
                    header.as_str(),
                    key.parse().unwrap(),
                );
            }
            AuthStrategy::Basic { username, password } => {
                let encoded = base64::encode(format!("{}:{}", username, password));
                request.headers_mut().insert(
                    "Authorization",
                    format!("Basic {}", encoded).parse().unwrap(),
                );
            }
            AuthStrategy::OAuth2 { client_id, client_secret } => {
                // OAuth2 implementation
                self.handle_oauth2(request, client_id, client_secret)?;
            }
        }
        Ok(())
    }

    fn handle_oauth2(&self, request: &mut Request, client_id: &str, client_secret: &str) -> Result<(), AuthError> {
        // OAuth2 token exchange logic
        todo!()
    }
}

// ✅ Context that uses the strategy
pub struct HttpClient {
    client: reqwest::Client,
    auth_strategy: Option<AuthStrategy>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            auth_strategy: None,
        }
    }

    pub fn with_auth(mut self, strategy: AuthStrategy) -> Self {
        self.auth_strategy = Some(strategy);
        self
    }

    pub async fn request(&self, url: &str) -> Result<Response, HttpError> {
        let mut request = self.client.get(url).build()?;

        if let Some(ref auth) = self.auth_strategy {
            auth.apply_to_request(&mut request)?;
        }

        let response = self.client.execute(request).await?;
        Ok(response)
    }
}
```

### Command Pattern with Undo
```rust
// ✅ Command pattern for operations with undo capability
pub trait Command {
    type Error;

    fn execute(&mut self) -> Result<(), Self::Error>;
    fn undo(&mut self) -> Result<(), Self::Error>;
    fn description(&self) -> &str;
}

#[derive(Debug)]
pub struct CreateUserCommand {
    user_service: Arc<UserService>,
    user_data: User,
    created_user_id: Option<UserId>,
}

impl CreateUserCommand {
    pub fn new(user_service: Arc<UserService>, user_data: User) -> Self {
        Self {
            user_service,
            user_data,
            created_user_id: None,
        }
    }
}

impl Command for CreateUserCommand {
    type Error = UserServiceError;

    fn execute(&mut self) -> Result<(), Self::Error> {
        let user = self.user_service.create_user(&self.user_data)?;
        self.created_user_id = Some(user.id);
        Ok(())
    }

    fn undo(&mut self) -> Result<(), Self::Error> {
        if let Some(user_id) = self.created_user_id.take() {
            self.user_service.delete_user(user_id)?;
        }
        Ok(())
    }

    fn description(&self) -> &str {
        "Create user"
    }
}

// ✅ Command invoker with history
pub struct CommandHistory {
    executed_commands: Vec<Box<dyn Command<Error = Box<dyn std::error::Error>>>>,
    current_position: usize,
}

impl CommandHistory {
    pub fn new() -> Self {
        Self {
            executed_commands: Vec::new(),
            current_position: 0,
        }
    }

    pub fn execute<C>(&mut self, mut command: C) -> Result<(), C::Error>
    where
        C: Command + 'static,
        C::Error: Into<Box<dyn std::error::Error>>,
    {
        command.execute()?;

        // Remove any commands after current position (when redoing after undo)
        self.executed_commands.truncate(self.current_position);

        // Add the new command
        self.executed_commands.push(Box::new(command));
        self.current_position += 1;

        Ok(())
    }

    pub fn undo(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.current_position > 0 {
            self.current_position -= 1;
            self.executed_commands[self.current_position].undo()?;
        }
        Ok(())
    }

    pub fn redo(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.current_position < self.executed_commands.len() {
            self.executed_commands[self.current_position].execute()?;
            self.current_position += 1;
        }
        Ok(())
    }
}
```

### Observer Pattern with Async
```rust
use tokio::sync::broadcast;

// ✅ Event-driven observer pattern with async support
#[derive(Debug, Clone)]
pub enum DomainEvent {
    UserCreated { user_id: UserId, email: String },
    UserUpdated { user_id: UserId, changes: Vec<String> },
    UserDeleted { user_id: UserId },
    OrderPlaced { order_id: OrderId, user_id: UserId, amount: Decimal },
}

#[async_trait::async_trait]
pub trait EventHandler {
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError>;
    fn interested_in(&self) -> Vec<std::mem::Discriminant<DomainEvent>>;
}

pub struct EmailNotificationHandler {
    email_service: Arc<EmailService>,
}

#[async_trait::async_trait]
impl EventHandler for EmailNotificationHandler {
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError> {
        match event {
            DomainEvent::UserCreated { email, .. } => {
                self.email_service.send_welcome_email(email).await?;
            }
            DomainEvent::OrderPlaced { user_id, amount, .. } => {
                let user = self.get_user(*user_id).await?;
                self.email_service.send_order_confirmation(&user.email, *amount).await?;
            }
            _ => {}
        }
        Ok(())
    }

    fn interested_in(&self) -> Vec<std::mem::Discriminant<DomainEvent>> {
        vec![
            std::mem::discriminant(&DomainEvent::UserCreated { user_id: UserId::new(), email: String::new() }),
            std::mem::discriminant(&DomainEvent::OrderPlaced {
                order_id: OrderId::new(),
                user_id: UserId::new(),
                amount: Decimal::ZERO
            }),
        ]
    }
}

// ✅ Event bus for managing observers
pub struct EventBus {
    sender: broadcast::Sender<DomainEvent>,
    handlers: Vec<Arc<dyn EventHandler + Send + Sync>>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        Self {
            sender,
            handlers: Vec::new(),
        }
    }

    pub fn subscribe(&mut self, handler: Arc<dyn EventHandler + Send + Sync>) {
        self.handlers.push(handler);
    }

    pub async fn publish(&self, event: DomainEvent) -> Result<(), EventError> {
        // Send to broadcast channel for other subscribers
        let _ = self.sender.send(event.clone());

        // Handle with registered handlers
        for handler in &self.handlers {
            let event_discriminant = std::mem::discriminant(&event);
            if handler.interested_in().contains(&event_discriminant) {
                if let Err(e) = handler.handle(&event).await {
                    tracing::error!("Event handler failed: {:?}", e);
                    // Continue with other handlers
                }
            }
        }

        Ok(())
    }

    pub fn subscribe_to_stream(&self) -> broadcast::Receiver<DomainEvent> {
        self.sender.subscribe()
    }
}
```

## 🏛️ STRUCTURAL PATTERNS

### Adapter Pattern for External APIs
```rust
// ✅ Adapter pattern for integrating different payment providers
#[async_trait::async_trait]
pub trait PaymentProcessor {
    async fn process_payment(&self, payment: &Payment) -> Result<PaymentResult, PaymentError>;
    async fn refund_payment(&self, payment_id: &str, amount: Option<Decimal>) -> Result<RefundResult, PaymentError>;
}

// External Stripe API (different interface)
pub struct StripeClient {
    // Stripe-specific implementation
}

impl StripeClient {
    pub async fn charge(&self, amount_cents: u64, token: &str) -> Result<StripeCharge, StripeError> {
        // Stripe-specific charge logic
    }

    pub async fn create_refund(&self, charge_id: &str, amount_cents: Option<u64>) -> Result<StripeRefund, StripeError> {
        // Stripe-specific refund logic
    }
}

// ✅ Adapter to make Stripe compatible with our interface
pub struct StripeAdapter {
    client: StripeClient,
}

impl StripeAdapter {
    pub fn new(client: StripeClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl PaymentProcessor for StripeAdapter {
    async fn process_payment(&self, payment: &Payment) -> Result<PaymentResult, PaymentError> {
        let amount_cents = (payment.amount * 100).to_u64().ok_or(PaymentError::InvalidAmount)?;

        let charge = self.client
            .charge(amount_cents, &payment.token)
            .await
            .map_err(|e| PaymentError::ProviderError(e.to_string()))?;

        Ok(PaymentResult {
            id: charge.id,
            status: match charge.status.as_str() {
                "succeeded" => PaymentStatus::Completed,
                "pending" => PaymentStatus::Pending,
                "failed" => PaymentStatus::Failed,
                _ => PaymentStatus::Unknown,
            },
            amount: payment.amount,
            fees: charge.fees.map(|f| Decimal::from(f) / 100),
        })
    }

    async fn refund_payment(&self, payment_id: &str, amount: Option<Decimal>) -> Result<RefundResult, PaymentError> {
        let amount_cents = amount.map(|a| (a * 100).to_u64().unwrap());

        let refund = self.client
            .create_refund(payment_id, amount_cents)
            .await
            .map_err(|e| PaymentError::ProviderError(e.to_string()))?;

        Ok(RefundResult {
            id: refund.id,
            amount: Decimal::from(refund.amount) / 100,
            status: RefundStatus::Completed,
        })
    }
}

// ✅ Similar adapter for PayPal
pub struct PayPalAdapter {
    client: PayPalClient,
}

#[async_trait::async_trait]
impl PaymentProcessor for PayPalAdapter {
    async fn process_payment(&self, payment: &Payment) -> Result<PaymentResult, PaymentError> {
        // PayPal-specific implementation
    }

    async fn refund_payment(&self, payment_id: &str, amount: Option<Decimal>) -> Result<RefundResult, PaymentError> {
        // PayPal-specific implementation
    }
}

// ✅ Payment service using any adapter
pub struct PaymentService {
    processor: Arc<dyn PaymentProcessor + Send + Sync>,
}

impl PaymentService {
    pub fn new(processor: Arc<dyn PaymentProcessor + Send + Sync>) -> Self {
        Self { processor }
    }

    pub async fn charge_customer(&self, payment: Payment) -> Result<PaymentResult, PaymentError> {
        self.processor.process_payment(&payment).await
    }
}
```

### Decorator Pattern with Middleware
```rust
// ✅ Decorator pattern for HTTP middleware
#[async_trait::async_trait]
pub trait HttpHandler {
    async fn handle(&self, request: Request) -> Result<Response, HttpError>;
}

// Base handler
pub struct BaseHandler;

#[async_trait::async_trait]
impl HttpHandler for BaseHandler {
    async fn handle(&self, request: Request) -> Result<Response, HttpError> {
        // Basic request handling
        Ok(Response::new("Hello World".into()))
    }
}

// ✅ Logging decorator
pub struct LoggingDecorator<H: HttpHandler> {
    inner: H,
}

impl<H: HttpHandler> LoggingDecorator<H> {
    pub fn new(inner: H) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<H: HttpHandler + Send + Sync> HttpHandler for LoggingDecorator<H> {
    async fn handle(&self, request: Request) -> Result<Response, HttpError> {
        let start = std::time::Instant::now();
        let method = request.method().clone();
        let uri = request.uri().clone();

        tracing::info!("Incoming request: {} {}", method, uri);

        let result = self.inner.handle(request).await;

        let duration = start.elapsed();
        match &result {
            Ok(response) => {
                tracing::info!(
                    "Request completed: {} {} -> {} in {:?}",
                    method, uri, response.status(), duration
                );
            }
            Err(e) => {
                tracing::error!(
                    "Request failed: {} {} -> {:?} in {:?}",
                    method, uri, e, duration
                );
            }
        }

        result
    }
}

// ✅ Rate limiting decorator
pub struct RateLimitDecorator<H: HttpHandler> {
    inner: H,
    rate_limiter: Arc<RateLimiter>,
}

impl<H: HttpHandler> RateLimitDecorator<H> {
    pub fn new(inner: H, rate_limiter: Arc<RateLimiter>) -> Self {
        Self { inner, rate_limiter }
    }
}

#[async_trait::async_trait]
impl<H: HttpHandler + Send + Sync> HttpHandler for RateLimitDecorator<H> {
    async fn handle(&self, request: Request) -> Result<Response, HttpError> {
        let client_ip = extract_client_ip(&request)?;

        self.rate_limiter.check_rate_limit(&client_ip).await
            .map_err(|_| HttpError::RateLimited)?;

        self.inner.handle(request).await
    }
}

// ✅ Composition of decorators
let handler = RateLimitDecorator::new(
    LoggingDecorator::new(
        BaseHandler
    ),
    rate_limiter
);
```

## 🧵 CONCURRENCY PATTERNS

### Actor Pattern with Tokio
```rust
use tokio::sync::{mpsc, oneshot};

// ✅ Actor pattern for managing state with message passing
#[derive(Debug)]
pub enum UserActorMessage {
    GetUser {
        user_id: UserId,
        respond_to: oneshot::Sender<Result<User, UserError>>,
    },
    UpdateUser {
        user_id: UserId,
        updates: UserUpdates,
        respond_to: oneshot::Sender<Result<User, UserError>>,
    },
    DeleteUser {
        user_id: UserId,
        respond_to: oneshot::Sender<Result<(), UserError>>,
    },
}

pub struct UserActor {
    receiver: mpsc::Receiver<UserActorMessage>,
    repository: Arc<dyn UserRepository + Send + Sync>,
    cache: DashMap<UserId, User>,
}

impl UserActor {
    pub fn new(repository: Arc<dyn UserRepository + Send + Sync>) -> (Self, UserActorHandle) {
        let (sender, receiver) = mpsc::channel(100);
        let actor = Self {
            receiver,
            repository,
            cache: DashMap::new(),
        };
        let handle = UserActorHandle { sender };
        (actor, handle)
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }

    async fn handle_message(&mut self, msg: UserActorMessage) {
        match msg {
            UserActorMessage::GetUser { user_id, respond_to } => {
                let result = self.get_user_internal(user_id).await;
                let _ = respond_to.send(result);
            }
            UserActorMessage::UpdateUser { user_id, updates, respond_to } => {
                let result = self.update_user_internal(user_id, updates).await;
                let _ = respond_to.send(result);
            }
            UserActorMessage::DeleteUser { user_id, respond_to } => {
                let result = self.delete_user_internal(user_id).await;
                let _ = respond_to.send(result);
            }
        }
    }

    async fn get_user_internal(&self, user_id: UserId) -> Result<User, UserError> {
        // Check cache first
        if let Some(user) = self.cache.get(&user_id) {
            return Ok(user.clone());
        }

        // Fetch from repository
        let user = self.repository.find_by_id(user_id).await?
            .ok_or(UserError::NotFound { user_id })?;

        // Cache the result
        self.cache.insert(user_id, user.clone());

        Ok(user)
    }

    async fn update_user_internal(&mut self, user_id: UserId, updates: UserUpdates) -> Result<User, UserError> {
        let updated_user = self.repository.update(user_id, updates).await?;

        // Update cache
        self.cache.insert(user_id, updated_user.clone());

        Ok(updated_user)
    }

    async fn delete_user_internal(&mut self, user_id: UserId) -> Result<(), UserError> {
        self.repository.delete(user_id).await?;

        // Remove from cache
        self.cache.remove(&user_id);

        Ok(())
    }
}

// ✅ Handle for communicating with the actor
#[derive(Clone)]
pub struct UserActorHandle {
    sender: mpsc::Sender<UserActorMessage>,
}

impl UserActorHandle {
    pub async fn get_user(&self, user_id: UserId) -> Result<User, UserError> {
        let (respond_to, response) = oneshot::channel();

        self.sender
            .send(UserActorMessage::GetUser { user_id, respond_to })
            .await
            .map_err(|_| UserError::ActorUnavailable)?;

        response.await
            .map_err(|_| UserError::ActorUnavailable)?
    }

    pub async fn update_user(&self, user_id: UserId, updates: UserUpdates) -> Result<User, UserError> {
        let (respond_to, response) = oneshot::channel();

        self.sender
            .send(UserActorMessage::UpdateUser { user_id, updates, respond_to })
            .await
            .map_err(|_| UserError::ActorUnavailable)?;

        response.await
            .map_err(|_| UserError::ActorUnavailable)?
    }
}

// ✅ Starting the actor system
pub async fn start_user_actor(repository: Arc<dyn UserRepository + Send + Sync>) -> UserActorHandle {
    let (actor, handle) = UserActor::new(repository);

    tokio::spawn(async move {
        actor.run().await;
    });

    handle
}
```

## ✅ DESIGN PATTERNS CHECKLIST

```markdown
### Design Patterns Implementation Verification
- [ ] Builder pattern used for complex configuration objects
- [ ] Factory pattern for creating related object families
- [ ] Strategy pattern for runtime algorithm selection
- [ ] Command pattern for operations requiring undo/redo
- [ ] Observer pattern for event-driven architecture
- [ ] Adapter pattern for external API integration
- [ ] Decorator pattern for cross-cutting concerns
- [ ] Actor pattern for concurrent state management
- [ ] Type-state pattern for compile-time validation
- [ ] Repository pattern for data access abstraction
- [ ] Dependency injection for testability
- [ ] Event sourcing for audit trails (when applicable)
- [ ] CQRS separation for read/write operations (when applicable)
- [ ] Circuit breaker for resilience patterns
- [ ] Retry pattern with exponential backoff
```

This design patterns guide provides battle-tested solutions for common architectural challenges in Rust applications.
---
description:
globs:
alwaysApply: false
---
# ⚡ RUST PERFORMANCE OPTIMIZATION

> **TL;DR:** Performance optimization strategies for Rust applications, focusing on zero-cost abstractions, memory management, and profiling-driven optimization.

## 🔍 PERFORMANCE OPTIMIZATION STRATEGY

```mermaid
graph TD
    Start["Performance Issue"] --> Measure["Profile & Measure"]

    Measure --> Bottleneck{"Bottleneck<br>Type?"}

    Bottleneck -->|CPU| CPUOpt["CPU Optimization"]
    Bottleneck -->|Memory| MemOpt["Memory Optimization"]
    Bottleneck -->|I/O| IOOpt["I/O Optimization"]
    Bottleneck -->|Concurrency| ConcOpt["Concurrency Optimization"]

    CPUOpt --> SIMD["SIMD Vectorization"]
    CPUOpt --> Algorithms["Algorithm Optimization"]
    CPUOpt --> CompileTime["Compile-Time Optimization"]

    MemOpt --> Allocation["Allocation Strategy"]
    MemOpt --> DataStructure["Data Structure Choice"]
    MemOpt --> Caching["Caching Patterns"]

    IOOpt --> Buffering["Buffering Strategy"]
    IOOpt --> AsyncIO["Async I/O Patterns"]
    IOOpt --> Batching["Request Batching"]

    ConcOpt --> Parallelism["Parallel Processing"]
    ConcOpt --> Channels["Channel Optimization"]
    ConcOpt --> LockFree["Lock-Free Structures"]

    SIMD --> Verify["Benchmark & Verify"]
    Algorithms --> Verify
    CompileTime --> Verify
    Allocation --> Verify
    DataStructure --> Verify
    Caching --> Verify
    Buffering --> Verify
    AsyncIO --> Verify
    Batching --> Verify
    Parallelism --> Verify
    Channels --> Verify
    LockFree --> Verify

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Measure fill:#ffa64d,stroke:#cc7a30,color:white
    style CPUOpt fill:#4dbb5f,stroke:#36873f,color:white
    style MemOpt fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 PERFORMANCE PRINCIPLES

### Measure First, Optimize Second
```rust
// ✅ Always profile before optimizing
use std::time::Instant;

#[cfg(feature = "profiling")]
macro_rules! time_it {
    ($name:expr, $block:block) => {{
        let start = Instant::now();
        let result = $block;
        let duration = start.elapsed();
        tracing::info!("{} took {:?}", $name, duration);
        result
    }};
}

#[cfg(not(feature = "profiling"))]
macro_rules! time_it {
    ($name:expr, $block:block) => {
        $block
    };
}

// Usage
fn process_data(data: &[u8]) -> Vec<u8> {
    time_it!("process_data", {
        // Expensive computation here
        data.iter().map(|&b| b.wrapping_mul(2)).collect()
    })
}
```

## 🏗️ MEMORY OPTIMIZATION

### String and Allocation Management
```rust
use std::borrow::Cow;

// ✅ Use Cow for flexible string handling
pub fn process_text<'a>(input: &'a str) -> Cow<'a, str> {
    if input.contains("old") {
        Cow::Owned(input.replace("old", "new"))
    } else {
        Cow::Borrowed(input)
    }
}

// ✅ Pre-allocate with known capacity
pub fn build_large_string(items: &[&str]) -> String {
    let total_len = items.iter().map(|s| s.len()).sum::<usize>();
    let mut result = String::with_capacity(total_len + items.len() - 1);

    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            result.push(' ');
        }
        result.push_str(item);
    }
    result
}

// ✅ Use Vec::with_capacity for known sizes
pub fn process_numbers(count: usize) -> Vec<i32> {
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(i as i32 * 2);
    }
    result
}

// ❌ Avoid repeated allocations
// fn bad_string_building(items: &[&str]) -> String {
//     let mut result = String::new();
//     for item in items {
//         result = result + item + " ";  // New allocation each time
//     }
//     result
// }
```

### Smart Pointer Optimization
```rust
use std::rc::Rc;
use std::sync::Arc;

// ✅ Use Rc for single-threaded shared ownership
#[derive(Debug, Clone)]
pub struct ConfigManager {
    config: Rc<Config>,
}

impl ConfigManager {
    pub fn new(config: Config) -> Self {
        Self {
            config: Rc::new(config),
        }
    }

    // Cheap to clone - only increments reference count
    pub fn get_config(&self) -> Rc<Config> {
        self.config.clone()
    }
}

// ✅ Use Arc for multi-threaded scenarios
#[derive(Debug, Clone)]
pub struct ThreadSafeCache {
    data: Arc<DashMap<String, Vec<u8>>>,
}

// ✅ Pool expensive objects
pub struct ConnectionPool {
    connections: Vec<DatabaseConnection>,
    available: std::collections::VecDeque<usize>,
}

impl ConnectionPool {
    pub async fn get_connection(&mut self) -> Option<PooledConnection> {
        if let Some(index) = self.available.pop_front() {
            Some(PooledConnection {
                connection: &mut self.connections[index],
                pool_index: index,
            })
        } else {
            None
        }
    }
}
```

## 🔄 ITERATION OPTIMIZATION

### Iterator Patterns
```rust
// ✅ Chain iterators for efficiency
pub fn process_and_filter(data: &[i32]) -> Vec<i32> {
    data.iter()
        .filter(|&&x| x > 0)
        .map(|&x| x * 2)
        .filter(|&x| x < 1000)
        .collect()
}

// ✅ Use fold for accumulation
pub fn sum_of_squares(numbers: &[i32]) -> i64 {
    numbers
        .iter()
        .map(|&x| x as i64)
        .map(|x| x * x)
        .fold(0, |acc, x| acc + x)
}

// ✅ Parallel iteration with rayon
use rayon::prelude::*;

pub fn parallel_process(data: &[f64]) -> Vec<f64> {
    data.par_iter()
        .map(|&x| expensive_computation(x))
        .collect()
}

fn expensive_computation(x: f64) -> f64 {
    // CPU-intensive operation
    x.powi(3) + x.powi(2) + x + 1.0
}

// ❌ Avoid collecting intermediate results
// fn inefficient_processing(data: &[i32]) -> Vec<i32> {
//     let filtered: Vec<_> = data.iter().filter(|&&x| x > 0).collect();
//     let mapped: Vec<_> = filtered.iter().map(|&x| x * 2).collect();
//     mapped.into_iter().filter(|&x| x < 1000).collect()
// }
```

### Custom Iterator Implementation
```rust
// ✅ Implement efficient custom iterators
pub struct ChunkIterator<'a, T> {
    data: &'a [T],
    chunk_size: usize,
    position: usize,
}

impl<'a, T> ChunkIterator<'a, T> {
    pub fn new(data: &'a [T], chunk_size: usize) -> Self {
        Self {
            data,
            chunk_size,
            position: 0,
        }
    }
}

impl<'a, T> Iterator for ChunkIterator<'a, T> {
    type Item = &'a [T];

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.data.len() {
            return None;
        }

        let end = std::cmp::min(self.position + self.chunk_size, self.data.len());
        let chunk = &self.data[self.position..end];
        self.position = end;
        Some(chunk)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.data.len() - self.position + self.chunk_size - 1) / self.chunk_size;
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for ChunkIterator<'a, T> {}
```

## 🧮 COMPUTATIONAL OPTIMIZATION

### Vectorization and SIMD
```rust
// ✅ Use SIMD when available
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub fn sum_f32_slice(values: &[f32]) -> f32 {
    if is_x86_feature_detected!("avx2") {
        unsafe { sum_f32_avx2(values) }
    } else {
        values.iter().sum()
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_f32_avx2(values: &[f32]) -> f32 {
    let mut sum = _mm256_setzero_ps();
    let chunks = values.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let v = _mm256_loadu_ps(chunk.as_ptr());
        sum = _mm256_add_ps(sum, v);
    }

    // Extract the sum from the vector
    let mut result = [0.0f32; 8];
    _mm256_storeu_ps(result.as_mut_ptr(), sum);
    let vector_sum: f32 = result.iter().sum();

    // Add remainder
    vector_sum + remainder.iter().sum::<f32>()
}
```

### Lookup Tables and Memoization
```rust
use std::collections::HashMap;

// ✅ Use lookup tables for expensive computations
pub struct FibonacciCalculator {
    cache: HashMap<u64, u64>,
}

impl FibonacciCalculator {
    pub fn new() -> Self {
        let mut cache = HashMap::new();
        cache.insert(0, 0);
        cache.insert(1, 1);
        Self { cache }
    }

    pub fn fibonacci(&mut self, n: u64) -> u64 {
        if let Some(&result) = self.cache.get(&n) {
            return result;
        }

        let result = self.fibonacci(n - 1) + self.fibonacci(n - 2);
        self.cache.insert(n, result);
        result
    }
}

// ✅ Pre-computed lookup tables
pub struct SinTable {
    table: Vec<f64>,
    resolution: f64,
}

impl SinTable {
    pub fn new(resolution: usize) -> Self {
        let table: Vec<f64> = (0..resolution)
            .map(|i| {
                let angle = (i as f64) * 2.0 * std::f64::consts::PI / (resolution as f64);
                angle.sin()
            })
            .collect();

        Self {
            table,
            resolution: resolution as f64,
        }
    }

    pub fn sin_approx(&self, angle: f64) -> f64 {
        let normalized = angle % (2.0 * std::f64::consts::PI);
        let index = (normalized * self.resolution / (2.0 * std::f64::consts::PI)) as usize;
        self.table[index.min(self.table.len() - 1)]
    }
}
```

## 🔧 ASYNC PERFORMANCE

### Async Optimization Patterns
```rust
use tokio::task::JoinSet;
use futures::future::{join_all, try_join_all};

// ✅ Batch async operations
pub async fn fetch_user_data_batch(user_ids: &[UserId]) -> Result<Vec<User>, ServiceError> {
    const BATCH_SIZE: usize = 50;

    let mut results = Vec::with_capacity(user_ids.len());

    for chunk in user_ids.chunks(BATCH_SIZE) {
        let futures = chunk.iter().map(|&id| fetch_user_data(id));
        let batch_results = try_join_all(futures).await?;
        results.extend(batch_results);
    }

    Ok(results)
}

// ✅ Use bounded channels to prevent memory issues
pub async fn process_stream_with_backpressure() -> Result<(), ProcessingError> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(100); // Bounded channel

    // Producer task
    tokio::spawn(async move {
        for i in 0..1000 {
            if tx.send(i).await.is_err() {
                break;
            }
            // Producer will block when channel is full
        }
    });

    // Consumer task
    while let Some(item) = rx.recv().await {
        process_item(item).await?;
    }

    Ok(())
}

// ✅ Optimize async task spawning
pub async fn parallel_processing_optimized(items: Vec<ProcessingItem>) -> Vec<ProcessedResult> {
    let mut join_set = JoinSet::new();
    let concurrency_limit = num_cpus::get();

    for chunk in items.chunks(items.len() / concurrency_limit + 1) {
        let chunk = chunk.to_vec();
        join_set.spawn(async move {
            chunk.into_iter().map(process_item_sync).collect::<Vec<_>>()
        });
    }

    let mut results = Vec::new();
    while let Some(result) = join_set.join_next().await {
        if let Ok(chunk_results) = result {
            results.extend(chunk_results);
        }
    }

    results
}
```

## 📊 PROFILING AND BENCHMARKING

### Benchmarking with Criterion
```rust
// Cargo.toml
// [dev-dependencies]
// criterion = { version = "0.5", features = ["html_reports"] }

#[cfg(test)]
mod benches {
    use super::*;
    use criterion::{black_box, criterion_group, criterion_main, Criterion};

    fn bench_string_concatenation(c: &mut Criterion) {
        let data = vec!["hello"; 1000];

        c.bench_function("string_concat_push", |b| {
            b.iter(|| {
                let mut result = String::new();
                for s in &data {
                    result.push_str(black_box(s));
                }
                result
            })
        });

        c.bench_function("string_concat_join", |b| {
            b.iter(|| data.join(""))
        });

        c.bench_function("string_concat_capacity", |b| {
            b.iter(|| {
                let mut result = String::with_capacity(data.len() * 5);
                for s in &data {
                    result.push_str(black_box(s));
                }
                result
            })
        });
    }

    criterion_group!(benches, bench_string_concatenation);
    criterion_main!(benches);
}
```

### Memory Profiling
```rust
// Use instruments on macOS or valgrind on Linux
#[cfg(feature = "profiling")]
pub fn memory_intensive_operation() {
    // Add memory tracking
    let start_memory = get_memory_usage();

    // Your operation here
    let result = expensive_operation();

    let end_memory = get_memory_usage();
    println!("Memory used: {} bytes", end_memory - start_memory);
}

#[cfg(feature = "profiling")]
fn get_memory_usage() -> usize {
    // Platform-specific memory usage detection
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(contents) = fs::read_to_string("/proc/self/status") {
            for line in contents.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        return kb.parse::<usize>().unwrap_or(0) * 1024;
                    }
                }
            }
        }
    }
    0
}
```

## 🚨 PERFORMANCE ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Don't clone unnecessarily
// fn bad_function(data: Vec<String>) -> Vec<String> {
//     data.clone()  // Unnecessary clone
// }

// ✅ Take ownership or borrow
fn good_function(data: Vec<String>) -> Vec<String> {
    data  // Move ownership
}

// ❌ Don't use Vec when you need Set operations
// fn slow_contains(vec: &Vec<String>, item: &str) -> bool {
//     vec.iter().any(|s| s == item)  // O(n) lookup
// }

// ✅ Use appropriate data structures
use std::collections::HashSet;
fn fast_contains(set: &HashSet<String>, item: &str) -> bool {
    set.contains(item)  // O(1) lookup
}

// ❌ Don't collect unnecessarily
// fn wasteful_processing(data: &[i32]) -> i32 {
//     data.iter()
//         .filter(|&&x| x > 0)
//         .collect::<Vec<_>>()  // Unnecessary allocation
//         .iter()
//         .sum()
// }

// ✅ Chain operations
fn efficient_processing(data: &[i32]) -> i32 {
    data.iter()
        .filter(|&&x| x > 0)
        .sum()
}
```

## 🎯 COMPILE-TIME OPTIMIZATION

### Cargo.toml Optimizations
```toml
[profile.release]
lto = true                    # Link-time optimization
codegen-units = 1            # Better optimization at cost of compile time
panic = "abort"              # Smaller binary size
strip = true                 # Remove debug symbols

[profile.release-with-debug]
inherits = "release"
debug = true                 # Keep debug info for profiling

# CPU-specific optimizations
[profile.release]
rustflags = ["-C", "target-cpu=native"]
```

### Feature Gates for Performance
```rust
// Cargo.toml
// [features]
// simd = []
// parallel = ["rayon"]

#[cfg(feature = "simd")]
pub fn fast_sum(data: &[f32]) -> f32 {
    sum_f32_slice(data)
}

#[cfg(not(feature = "simd"))]
pub fn fast_sum(data: &[f32]) -> f32 {
    data.iter().sum()
}

#[cfg(feature = "parallel")]
pub fn parallel_map<T, U, F>(data: &[T], f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> U + Sync,
{
    use rayon::prelude::*;
    data.par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
pub fn parallel_map<T, U, F>(data: &[T], f: F) -> Vec<U>
where
    F: Fn(&T) -> U,
{
    data.iter().map(f).collect()
}
```

## ✅ PERFORMANCE CHECKLIST

```markdown
### Performance Implementation Verification
- [ ] Profile before optimizing (use criterion for benchmarks)
- [ ] Pre-allocate collections with known capacity
- [ ] Use appropriate data structures (HashMap vs Vec for lookups)
- [ ] Leverage iterator chains instead of intermediate collections
- [ ] Consider parallel processing for CPU-intensive tasks
- [ ] Use Cow for flexible string handling
- [ ] Implement object pooling for expensive resources
- [ ] Use SIMD when appropriate and available
- [ ] Optimize async task spawning and batching
- [ ] Enable LTO and appropriate optimization flags
- [ ] Use bounded channels to prevent memory issues
- [ ] Implement memoization for expensive computations
- [ ] Choose between Arc/Rc based on threading needs
- [ ] Avoid unnecessary clones and allocations
- [ ] Use const generics for compile-time optimizations
```

This performance guide provides practical optimization strategies while maintaining Rust's safety guarantees and zero-cost abstraction principles.
---
description:
globs:
alwaysApply: false
---
# 🔐 RUST SECURITY BEST PRACTICES

> **TL;DR:** Security-focused programming patterns for Rust applications, covering input validation, cryptography, secrets management, and secure coding practices.

## 🔍 SECURITY IMPLEMENTATION STRATEGY

```mermaid
graph TD
    Start["Security Assessment"] --> ThreatModel["Threat Modeling"]

    ThreatModel --> InputSecurity{"Input<br>Validation?"}
    ThreatModel --> AuthSecurity{"Authentication<br>Required?"}
    ThreatModel --> DataSecurity{"Data<br>Protection?"}
    ThreatModel --> AccessSecurity{"Access<br>Control?"}

    InputSecurity -->|Yes| Validation["Input Validation"]
    InputSecurity -->|No| InputDone["✓"]

    AuthSecurity -->|Yes| PasswordHash["Password Hashing"]
    AuthSecurity -->|No| AuthDone["✓"]

    DataSecurity -->|Yes| Encryption["Data Encryption"]
    DataSecurity -->|No| DataDone["✓"]

    AccessSecurity -->|Yes| RBAC["Role-Based Access Control"]
    AccessSecurity -->|No| AccessDone["✓"]

    Validation --> PathTraversal["Path Traversal Prevention"]
    PathTraversal --> SQLInjection["SQL Injection Prevention"]

    PasswordHash --> Argon2["Argon2 Implementation"]
    Argon2 --> JWT["JWT Token Security"]

    Encryption --> SecretsManagement["Secrets Management"]
    SecretsManagement --> AESGCMEncryption["AES-GCM Encryption"]

    RBAC --> RateLimiting["Rate Limiting"]
    RateLimiting --> Audit["Security Audit Logging"]

    SQLInjection --> SecurityDone["Security Verified"]
    JWT --> SecurityDone
    AESGCMEncryption --> SecurityDone
    Audit --> SecurityDone
    InputDone --> SecurityDone
    AuthDone --> SecurityDone
    DataDone --> SecurityDone
    AccessDone --> SecurityDone

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style ThreatModel fill:#ffa64d,stroke:#cc7a30,color:white
    style Argon2 fill:#4dbb5f,stroke:#36873f,color:white
    style SecurityDone fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 SECURITY PRINCIPLES

### Input Validation and Sanitization
```rust
use validator::{Validate, ValidationError};
use regex::Regex;
use std::collections::HashSet;

// ✅ Always validate and sanitize user input
#[derive(Debug, Clone, Validate)]
pub struct UserRegistration {
    #[validate(email, message = "Invalid email format")]
    pub email: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    #[validate(custom = "validate_password_strength")]
    pub password: String,

    #[validate(length(min = 2, max = 50, message = "Username must be 2-50 characters"))]
    #[validate(regex = "USERNAME_REGEX", message = "Username contains invalid characters")]
    pub username: String,
}

lazy_static::lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    static ref FORBIDDEN_PASSWORDS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("password");
        set.insert("123456");
        set.insert("admin");
        set.insert("qwerty");
        set
    };
}

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    // Check for forbidden passwords
    if FORBIDDEN_PASSWORDS.contains(&password.to_lowercase().as_str()) {
        return Err(ValidationError::new("forbidden_password"));
    }

    // Require at least one uppercase, lowercase, digit, and special character
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(ValidationError::new("weak_password"));
    }

    Ok(())
}

// ✅ SQL injection prevention with parameterized queries
pub async fn find_user_by_email(
    pool: &sqlx::PgPool,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    // ✅ Safe: Uses parameterized query
    sqlx::query_as::<_, User>(
        "SELECT id, email, username FROM users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

// ❌ NEVER: String interpolation vulnerable to SQL injection
// let query = format!("SELECT * FROM users WHERE email = '{}'", email);
```

### Path Traversal Prevention
```rust
use std::path::{Path, PathBuf};

// ✅ Safe file path handling
pub fn safe_file_access(base_dir: &Path, user_path: &str) -> Result<PathBuf, SecurityError> {
    // Normalize and resolve the path
    let requested_path = base_dir.join(user_path);
    let canonical_path = requested_path.canonicalize()
        .map_err(|_| SecurityError::InvalidPath)?;

    // Ensure the canonical path is within the base directory
    if !canonical_path.starts_with(base_dir) {
        return Err(SecurityError::PathTraversal);
    }

    Ok(canonical_path)
}

// ✅ File upload with validation
pub async fn upload_file(
    file_data: &[u8],
    filename: &str,
    upload_dir: &Path,
) -> Result<PathBuf, SecurityError> {
    // Validate filename
    if filename.contains("..") || filename.contains('/') || filename.contains('\') {
        return Err(SecurityError::InvalidFilename);
    }

    // Check file size
    const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    if file_data.len() > MAX_FILE_SIZE {
        return Err(SecurityError::FileTooLarge);
    }

    // Validate file type by magic bytes
    let file_type = detect_file_type(file_data)?;
    if !is_allowed_file_type(&file_type) {
        return Err(SecurityError::DisallowedFileType);
    }

    // Generate safe filename
    let safe_filename = sanitize_filename(filename);
    let file_path = upload_dir.join(safe_filename);

    tokio::fs::write(&file_path, file_data).await
        .map_err(|_| SecurityError::FileWriteError)?;

    Ok(file_path)
}

fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}
```

## 🔑 CRYPTOGRAPHY AND HASHING

### Password Hashing with Argon2
```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};

// ✅ Secure password hashing with Argon2 (recommended)
pub struct PasswordService;

impl PasswordService {
    pub fn hash_password(password: &str) -> Result<String, SecurityError> {
        let salt = SaltString::generate(&mut OsRng);

        // Use Argon2id (default) with recommended parameters
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| SecurityError::HashingError)?;

        Ok(password_hash.to_string())
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, SecurityError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|_| SecurityError::InvalidHash)?;

        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    // ✅ Custom Argon2 configuration for high-security applications
    pub fn hash_password_high_security(password: &str) -> Result<String, SecurityError> {
        use argon2::{Algorithm, Params, Version};

        let salt = SaltString::generate(&mut OsRng);

        // Custom parameters for higher security (adjust based on performance requirements)
        let params = Params::new(
            65536,  // m_cost (memory cost) - 64 MB
            3,      // t_cost (time cost) - 3 iterations
            4,      // p_cost (parallelism) - 4 threads
            Some(32) // output length
        ).map_err(|_| SecurityError::HashingError)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| SecurityError::HashingError)?;

        Ok(password_hash.to_string())
    }
}
```

### JWT Token Security
```rust
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // Subject (user ID)
    pub exp: i64,         // Expiration time
    pub iat: i64,         // Issued at
    pub jti: String,      // JWT ID for revocation
    pub scope: Vec<String>, // User permissions
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

impl JwtService {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
        }
    }

    pub fn create_token(&self, user_id: &str, scopes: Vec<String>) -> Result<String, SecurityError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(24);

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            scope: scopes,
        };

        let mut header = Header::new(self.algorithm);
        header.kid = Some("1".to_string()); // Key ID for key rotation

        encode(&header, &claims, &self.encoding_key)
            .map_err(|_| SecurityError::TokenCreationError)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, SecurityError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| SecurityError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
```

## 🔒 SECRETS MANAGEMENT

### Environment Variable Security
```rust
use std::env;
use zeroize::Zeroize;

// ✅ Secure secret handling
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret {
    value: String,
}

impl Secret {
    pub fn from_env(key: &str) -> Result<Self, SecurityError> {
        let value = env::var(key)
            .map_err(|_| SecurityError::MissingSecret)?;

        if value.is_empty() {
            return Err(SecurityError::EmptySecret);
        }

        Ok(Self { value })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    // ❌ Never implement Display or Debug for secrets
    // This prevents accidental logging
}

// ✅ Configuration with secure defaults
#[derive(Debug)]
pub struct SecurityConfig {
    pub jwt_secret: Secret,
    pub database_url: Secret,
    pub encryption_key: Secret,
    pub session_timeout: Duration,
    pub max_login_attempts: u32,
    pub rate_limit_per_minute: u32,
}

impl SecurityConfig {
    pub fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            jwt_secret: Secret::from_env("JWT_SECRET")?,
            database_url: Secret::from_env("DATABASE_URL")?,
            encryption_key: Secret::from_env("ENCRYPTION_KEY")?,
            session_timeout: Duration::minutes(
                env::var("SESSION_TIMEOUT_MINUTES")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .unwrap_or(30)
            ),
            max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
        })
    }
}
```

### Data Encryption
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use rand::{RngCore, rngs::OsRng};

pub struct EncryptionService {
    cipher: Aes256Gcm,
}

impl EncryptionService {
    pub fn new(key: &[u8]) -> Result<Self, SecurityError> {
        if key.len() != 32 {
            return Err(SecurityError::InvalidKeyLength);
        }

        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SecurityError::EncryptionError)?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if encrypted_data.len() < 12 {
            return Err(SecurityError::InvalidCiphertext);
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SecurityError::DecryptionError)
    }
}

// ✅ Secure data structure for sensitive information
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveData {
    data: Vec<u8>,
}

impl SensitiveData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}
```

## 🛡️ ACCESS CONTROL AND AUTHORIZATION

### Role-Based Access Control (RBAC)
```rust
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Permission {
    UserRead,
    UserWrite,
    UserDelete,
    AdminAccess,
    SystemConfig,
}

#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub permissions: HashSet<Permission>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub roles: HashSet<String>,
}

pub struct AuthorizationService {
    roles: HashMap<String, Role>,
    user_sessions: HashMap<String, User>,
}

impl AuthorizationService {
    pub fn new() -> Self {
        let mut roles = HashMap::new();

        // Define standard roles
        roles.insert("user".to_string(), Role {
            name: "user".to_string(),
            permissions: [Permission::UserRead].into_iter().collect(),
        });

        roles.insert("admin".to_string(), Role {
            name: "admin".to_string(),
            permissions: [
                Permission::UserRead,
                Permission::UserWrite,
                Permission::UserDelete,
                Permission::AdminAccess,
            ].into_iter().collect(),
        });

        roles.insert("super_admin".to_string(), Role {
            name: "super_admin".to_string(),
            permissions: [
                Permission::UserRead,
                Permission::UserWrite,
                Permission::UserDelete,
                Permission::AdminAccess,
                Permission::SystemConfig,
            ].into_iter().collect(),
        });

        Self {
            roles,
            user_sessions: HashMap::new(),
        }
    }

    pub fn check_permission(&self, user_id: &str, permission: &Permission) -> bool {
        if let Some(user) = self.user_sessions.get(user_id) {
            for role_name in &user.roles {
                if let Some(role) = self.roles.get(role_name) {
                    if role.permissions.contains(permission) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn require_permission(&self, user_id: &str, permission: Permission) -> Result<(), SecurityError> {
        if self.check_permission(user_id, &permission) {
            Ok(())
        } else {
            Err(SecurityError::InsufficientPermissions)
        }
    }
}

// ✅ Authorization middleware for web frameworks
pub async fn require_auth_middleware(
    auth_service: &AuthorizationService,
    user_id: &str,
    required_permission: Permission,
) -> Result<(), SecurityError> {
    auth_service.require_permission(user_id, required_permission)
}
```

## 🚨 RATE LIMITING AND DDOS PROTECTION

### Rate Limiting Implementation
```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    limits: RwLock<HashMap<String, RateLimit>>,
    max_requests: u32,
    window_duration: Duration,
}

#[derive(Debug)]
struct RateLimit {
    requests: Vec<Instant>,
    last_cleanup: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            limits: RwLock::new(HashMap::new()),
            max_requests,
            window_duration,
        }
    }

    pub async fn check_rate_limit(&self, identifier: &str) -> Result<(), SecurityError> {
        let now = Instant::now();
        let mut limits = self.limits.write().await;

        let rate_limit = limits.entry(identifier.to_string()).or_insert(RateLimit {
            requests: Vec::new(),
            last_cleanup: now,
        });

        // Cleanup old requests
        if now.duration_since(rate_limit.last_cleanup) > self.window_duration {
            rate_limit.requests.retain(|&request_time| {
                now.duration_since(request_time) <= self.window_duration
            });
            rate_limit.last_cleanup = now;
        }

        // Check if limit exceeded
        if rate_limit.requests.len() >= self.max_requests as usize {
            return Err(SecurityError::RateLimitExceeded);
        }

        // Add current request
        rate_limit.requests.push(now);
        Ok(())
    }
}

// ✅ IP-based rate limiting for web endpoints
pub async fn rate_limit_by_ip(
    rate_limiter: &RateLimiter,
    ip_address: &str,
) -> Result<(), SecurityError> {
    rate_limiter.check_rate_limit(ip_address).await
}
```

## 🚨 SECURITY ERROR TYPES

### Comprehensive Security Errors
```rust
#[derive(thiserror::Error, Debug)]
pub enum SecurityError {
    #[error("Invalid email format")]
    InvalidEmail,

    #[error("Weak password")]
    WeakPassword,

    #[error("Path traversal attempt detected")]
    PathTraversal,

    #[error("Invalid file path")]
    InvalidPath,

    #[error("Invalid filename")]
    InvalidFilename,

    #[error("File too large")]
    FileTooLarge,

    #[error("Disallowed file type")]
    DisallowedFileType,

    #[error("File write error")]
    FileWriteError,

    #[error("Hashing error")]
    HashingError,

    #[error("Password verification error")]
    VerificationError,

    #[error("Invalid hash format")]
    InvalidHash,

    #[error("Token creation error")]
    TokenCreationError,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Missing secret configuration")]
    MissingSecret,

    #[error("Empty secret value")]
    EmptySecret,

    #[error("Invalid encryption key length")]
    InvalidKeyLength,

    #[error("Encryption failed")]
    EncryptionError,

    #[error("Decryption failed")]
    DecryptionError,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Session expired")]
    SessionExpired,

    #[error("Account locked")]
    AccountLocked,
}

impl SecurityError {
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidEmail
                | Self::WeakPassword
                | Self::PathTraversal
                | Self::InvalidPath
                | Self::InvalidFilename
                | Self::FileTooLarge
                | Self::DisallowedFileType
                | Self::InvalidToken
                | Self::InsufficientPermissions
                | Self::RateLimitExceeded
                | Self::AuthenticationRequired
        )
    }

    pub fn should_log_details(&self) -> bool {
        !self.is_client_error()
    }
}
```

## ✅ SECURITY CHECKLIST

```markdown
### Security Implementation Verification
- [ ] All user inputs are validated and sanitized
- [ ] SQL queries use parameterized statements
- [ ] File paths are validated against traversal attacks
- [ ] File uploads are validated by type and size
- [ ] Passwords are hashed with Argon2
- [ ] JWT tokens include expiration and proper validation
- [ ] Secrets are loaded from environment variables
- [ ] Sensitive data structures implement Zeroize
- [ ] Encryption uses authenticated encryption (AES-GCM)
- [ ] Role-based access control is implemented
- [ ] Rate limiting protects against abuse
- [ ] Error messages don't leak sensitive information
- [ ] Security headers are set in HTTP responses
- [ ] Input validation happens on both client and server
- [ ] Audit logging tracks security-relevant events
- [ ] Regular security updates are applied
- [ ] Cryptographic randomness uses secure sources
- [ ] Session management includes timeout and rotation
```

This security guide provides comprehensive protection patterns while maintaining usability and performance in Rust applications.
---
description:
globs:
alwaysApply: false
---
# 🔍 RUST TYPE SYSTEM BEST PRACTICES

> **TL;DR:** Leverage Rust's powerful type system for safety, performance, and expressiveness through newtype patterns, phantom types, and zero-cost abstractions.

## 🔍 TYPE SYSTEM DESIGN STRATEGY

```mermaid
graph TD
    Start["Type Design"] --> DomainCheck{"Domain-Specific<br>Types Needed?"}

    DomainCheck -->|Yes| NewtypePattern["Newtype Pattern"]
    DomainCheck -->|No| PrimitiveCheck{"Primitive<br>Obsession?"}

    NewtypePattern --> StateTracking{"State Tracking<br>Required?"}
    PrimitiveCheck -->|Yes| NewtypePattern
    PrimitiveCheck -->|No| TraitDesign["Trait Design"]

    StateTracking -->|Yes| PhantomTypes["Phantom Types"]
    StateTracking -->|No| ValidatedTypes["Validated Types"]

    PhantomTypes --> CompileTimeCheck["Compile-Time Validation"]
    ValidatedTypes --> RuntimeCheck["Runtime Validation"]

    CompileTimeCheck --> ZeroCost["Zero-Cost Abstractions"]
    RuntimeCheck --> ZeroCost
    TraitDesign --> ZeroCost

    ZeroCost --> ErrorModeling["Error Modeling"]
    ErrorModeling --> SafetyPatterns["Safety Patterns"]
    SafetyPatterns --> Performance["Performance Optimization"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style NewtypePattern fill:#4dbb5f,stroke:#36873f,color:white
    style PhantomTypes fill:#ffa64d,stroke:#cc7a30,color:white
    style ZeroCost fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 TYPE SAFETY PRINCIPLES

### Newtype Pattern for Domain Modeling
```rust
use derive_more::{Constructor, Display, From, Into};
use serde::{Deserialize, Serialize};
use std::fmt;

// ✅ Strong typing for domain concepts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Constructor, Display, From, Into)]
pub struct UserId(uuid::Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Constructor, Display, From, Into)]
pub struct ProductId(uuid::Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Constructor, Display, From, Into)]
pub struct OrderId(uuid::Uuid);

// ✅ Prevents mixing up IDs at compile time
fn process_order(user_id: UserId, product_id: ProductId) -> OrderId {
    // Compiler prevents: process_order(product_id, user_id)
    OrderId(uuid::Uuid::new_v4())
}

// ❌ Weak typing - prone to errors
// fn process_order(user_id: String, product_id: String) -> String
```

### Validated Types with Builder Pattern
```rust
use typed_builder::TypedBuilder;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, TypedBuilder, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Email {
    #[validate(email)]
    #[builder(setter(into))]
    value: String,
}

impl Email {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let email = Self { value: value.into() };
        email.validate()?;
        Ok(email)
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ✅ Usage - compile-time guarantee of valid email
let email = Email::new("user@example.com")?;
```

### Phantom Types for Compile-Time State
```rust
use std::marker::PhantomData;

// State types
pub struct Draft;
pub struct Published;
pub struct Archived;

// Document with compile-time state tracking
#[derive(Debug, Clone)]
pub struct Document<State> {
    id: DocumentId,
    title: String,
    content: String,
    _state: PhantomData<State>,
}

impl<State> Document<State> {
    pub fn id(&self) -> DocumentId {
        self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }
}

impl Document<Draft> {
    pub fn new(title: String, content: String) -> Self {
        Self {
            id: DocumentId::new(),
            title,
            content,
            _state: PhantomData,
        }
    }

    pub fn publish(self) -> Document<Published> {
        Document {
            id: self.id,
            title: self.title,
            content: self.content,
            _state: PhantomData,
        }
    }
}

impl Document<Published> {
    pub fn archive(self) -> Document<Archived> {
        Document {
            id: self.id,
            title: self.title,
            content: self.content,
            _state: PhantomData,
        }
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

impl Document<Archived> {
    pub fn restore(self) -> Document<Draft> {
        Document {
            id: self.id,
            title: self.title,
            content: self.content,
            _state: PhantomData,
        }
    }
}

// ✅ Usage - compiler prevents invalid state transitions
let draft = Document::<Draft>::new("Title".to_string(), "Content".to_string());
let published = draft.publish();
let archived = published.archive();
// Compiler error: draft.archive() - can't archive a draft
```

## 🔄 TRAIT DESIGN PATTERNS

### Trait Objects vs Generic Bounds
```rust
// ✅ Use generics for known types at compile time
pub fn process_items<T: Processable>(items: &[T]) -> Vec<T::Output> {
    items.iter().map(|item| item.process()).collect()
}

// ✅ Use trait objects for runtime polymorphism
pub struct EventBus {
    handlers: Vec<Box<dyn EventHandler>>,
}

impl EventBus {
    pub fn register_handler(&mut self, handler: Box<dyn EventHandler>) {
        self.handlers.push(handler);
    }

    pub fn dispatch(&self, event: &Event) {
        for handler in &self.handlers {
            handler.handle(event);
        }
    }
}

// ✅ Async trait pattern
#[async_trait::async_trait]
pub trait AsyncProcessor {
    type Error;
    type Output;

    async fn process(&self, input: &[u8]) -> Result<Self::Output, Self::Error>;
}
```

### Associated Types vs Generic Parameters
```rust
// ✅ Use associated types for tight coupling
pub trait Iterator {
    type Item;  // One Item type per Iterator implementation
    fn next(&mut self) -> Option<Self::Item>;
}

// ✅ Use generic parameters for flexibility
pub trait Convert<T, U> {
    fn convert(&self, input: T) -> U;
}

// Example: A single type can implement multiple conversions
impl Convert<String, i32> for NumberParser {
    fn convert(&self, input: String) -> i32 { /* ... */ }
}

impl Convert<String, f64> for NumberParser {
    fn convert(&self, input: String) -> f64 { /* ... */ }
}
```

## 📊 ENUM DESIGN PATTERNS

### Comprehensive Error Modeling
```rust
#[derive(thiserror::Error, Debug)]
pub enum UserServiceError {
    #[error("User not found: {user_id}")]
    NotFound { user_id: UserId },

    #[error("Email already exists: {email}")]
    EmailExists { email: Email },

    #[error("Database error: {source}")]
    Database {
        #[from]
        source: sqlx::Error,
    },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Permission denied: {action} requires {permission}")]
    PermissionDenied {
        action: String,
        permission: String,
    },
}

// ✅ Structured error handling with context
impl UserServiceError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Database { .. })
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "USER_NOT_FOUND",
            Self::EmailExists { .. } => "EMAIL_EXISTS",
            Self::Database { .. } => "DATABASE_ERROR",
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::PermissionDenied { .. } => "PERMISSION_DENIED",
        }
    }
}
```

### State Machine with Enums
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "camelCase")]
pub enum OrderStatus {
    Pending { items: Vec<OrderItem> },
    Processing { estimated_completion: DateTime<Utc> },
    Shipped { tracking_number: String, carrier: String },
    Delivered { delivery_time: DateTime<Utc> },
    Cancelled { reason: String, refund_issued: bool },
}

impl OrderStatus {
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Pending { .. } | Self::Processing { .. })
    }

    pub fn can_ship(&self) -> bool {
        matches!(self, Self::Processing { .. })
    }

    pub fn is_final(&self) -> bool {
        matches!(self, Self::Delivered { .. } | Self::Cancelled { .. })
    }
}

// ✅ Type-safe state transitions
impl Order {
    pub fn ship(mut self, tracking_number: String, carrier: String) -> Result<Self, OrderError> {
        match self.status {
            OrderStatus::Processing { .. } => {
                self.status = OrderStatus::Shipped { tracking_number, carrier };
                Ok(self)
            }
            _ => Err(OrderError::InvalidStateTransition {
                from: self.status.clone(),
                to: "Shipped".to_string(),
            }),
        }
    }
}
```

## 🛡️ SAFETY PATTERNS

### Option and Result Combinators
```rust
// ✅ Chain operations safely
fn process_user_data(user_id: UserId) -> Result<ProcessedData, ServiceError> {
    find_user(user_id)?
        .and_then(|user| user.profile.as_ref().ok_or(ServiceError::MissingProfile))
        .and_then(|profile| validate_profile(profile))
        .map(|profile| process_profile(profile))
}

// ✅ Use combinators for cleaner code
fn get_user_email(user_id: UserId) -> Option<Email> {
    find_user(user_id)
        .ok()
        .and_then(|user| user.email)
        .filter(|email| email.is_verified())
}

// ✅ Error conversion with context
fn create_user(request: CreateUserRequest) -> Result<User, UserServiceError> {
    validate_email(&request.email)
        .map_err(|e| UserServiceError::Validation { message: e.to_string() })?;

    repository
        .create_user(request)
        .await
        .map_err(UserServiceError::from)
}
```

### Custom Smart Pointers
```rust
use std::ops::{Deref, DerefMut};

// ✅ Validated wrapper that maintains invariants
#[derive(Debug)]
pub struct NonEmptyVec<T> {
    inner: Vec<T>,
}

impl<T> NonEmptyVec<T> {
    pub fn new(first: T) -> Self {
        Self {
            inner: vec![first],
        }
    }

    pub fn try_from_vec(vec: Vec<T>) -> Result<Self, EmptyVecError> {
        if vec.is_empty() {
            Err(EmptyVecError)
        } else {
            Ok(Self { inner: vec })
        }
    }

    pub fn push(&mut self, item: T) {
        self.inner.push(item);
    }

    pub fn first(&self) -> &T {
        // Safe to unwrap because we maintain the non-empty invariant
        self.inner.first().unwrap()
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
```

## 🎨 ZERO-COST ABSTRACTIONS

### Compile-Time Constants
```rust
// ✅ Use const generics for compile-time validation
#[derive(Debug, Clone)]
pub struct FixedArray<T, const N: usize> {
    data: [T; N],
}

impl<T: Default + Copy, const N: usize> FixedArray<T, N> {
    pub fn new() -> Self {
        Self {
            data: [T::default(); N],
        }
    }
}

// ✅ Type-level programming with const generics
pub struct Matrix<T, const ROWS: usize, const COLS: usize> {
    data: [[T; COLS]; ROWS],
}

impl<T, const ROWS: usize, const COLS: usize> Matrix<T, ROWS, COLS> {
    pub fn multiply<const OTHER_COLS: usize>(
        self,
        other: Matrix<T, COLS, OTHER_COLS>,
    ) -> Matrix<T, ROWS, OTHER_COLS>
    where
        T: Default + Copy + std::ops::Add<Output = T> + std::ops::Mul<Output = T>,
    {
        // Matrix multiplication with compile-time dimension checking
        todo!()
    }
}
```

### Builder with Type State
```rust
// ✅ Builder pattern with compile-time validation
pub struct ConfigBuilder<HasHost, HasPort> {
    host: Option<String>,
    port: Option<u16>,
    timeout: Option<Duration>,
    _marker: PhantomData<(HasHost, HasPort)>,
}

pub struct Missing;
pub struct Present;

impl ConfigBuilder<Missing, Missing> {
    pub fn new() -> Self {
        Self {
            host: None,
            port: None,
            timeout: None,
            _marker: PhantomData,
        }
    }
}

impl<HasPort> ConfigBuilder<Missing, HasPort> {
    pub fn host(self, host: String) -> ConfigBuilder<Present, HasPort> {
        ConfigBuilder {
            host: Some(host),
            port: self.port,
            timeout: self.timeout,
            _marker: PhantomData,
        }
    }
}

impl<HasHost> ConfigBuilder<HasHost, Missing> {
    pub fn port(self, port: u16) -> ConfigBuilder<HasHost, Present> {
        ConfigBuilder {
            host: self.host,
            port: Some(port),
            timeout: self.timeout,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasPort> ConfigBuilder<HasHost, HasPort> {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

// Only allow build when both host and port are set
impl ConfigBuilder<Present, Present> {
    pub fn build(self) -> Config {
        Config {
            host: self.host.unwrap(),
            port: self.port.unwrap(),
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
        }
    }
}

// ✅ Usage - compiler ensures required fields
let config = ConfigBuilder::new()
    .host("localhost".to_string())
    .port(8080)
    .timeout(Duration::from_secs(60))
    .build();
```

## 🚨 TYPE SYSTEM ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Weak typing - error prone
fn calculate_discount(price: f64, percentage: f64) -> f64 {
    // Could accidentally pass percentage as price
    price * (percentage / 100.0)
}

// ✅ Strong typing prevents errors
#[derive(Debug, Clone, Copy)]
pub struct Price(f64);

#[derive(Debug, Clone, Copy)]
pub struct Percentage(f64);

fn calculate_discount(price: Price, percentage: Percentage) -> Price {
    Price(price.0 * (percentage.0 / 100.0))
}

// ❌ Overuse of String for everything
// struct User {
//     id: String,
//     email: String,
//     status: String,
// }

// ✅ Proper typing
struct User {
    id: UserId,
    email: Email,
    status: UserStatus,
}

// ❌ Large enums with mixed concerns
// enum AppState {
//     Loading,
//     UserData(User),
//     Error(String),
//     DatabaseConnection(Database),
//     HttpRequest(Request),
// }

// ✅ Focused enums
enum LoadingState {
    Loading,
    Loaded(User),
    Failed(LoadError),
}
```

## ✅ TYPE SYSTEM CHECKLIST

```markdown
### Type System Implementation Verification
- [ ] Uses newtype pattern for domain concepts
- [ ] Phantom types for compile-time state tracking
- [ ] Associated types vs generics chosen appropriately
- [ ] Enums model state machines correctly
- [ ] Option/Result combinators used over unwrap
- [ ] Zero-cost abstractions leverage compile-time checks
- [ ] Builder patterns enforce required fields
- [ ] Error types are structured and informative
- [ ] No primitive obsession (avoid String/i32 for everything)
- [ ] Type safety prevents common runtime errors
- [ ] Const generics used for compile-time validation
- [ ] Trait objects vs generics chosen appropriately
```

This type system guide leverages Rust's powerful type system to catch errors at compile time and create more maintainable, expressive code.

---
description:
globs:
alwaysApply: false
---
# 🚨 RUST ERROR HANDLING STANDARDS

> **TL;DR:** Comprehensive error handling guidelines using thiserror for libraries and anyhow for binaries, with centralized error definitions per crate.

## 🔍 ERROR HANDLING STRATEGY SELECTION

```mermaid
graph TD
    Project["Project Analysis"] --> CrateType{"Crate Type?"}

    CrateType -->|"lib"| LibCrate["Library Crate"]
    CrateType -->|"bin"| BinCrate["Binary Crate"]

    LibCrate --> ThiserrorChoice["Use thiserror"]
    BinCrate --> AnyhowChoice["Use anyhow"]

    ThiserrorChoice --> LibFeatures["Library Features:"]
    AnyhowChoice --> BinFeatures["Binary Features:"]

    LibFeatures --> Structured["• Structured errors"]
    LibFeatures --> Derived["• Derive Error trait"]
    LibFeatures --> Transparent["• Error forwarding"]
    LibFeatures --> Documentation["• Error documentation"]

    BinFeatures --> Simple["• Simple error handling"]
    BinFeatures --> Context["• Rich context"]
    BinFeatures --> Chaining["• Error chaining"]
    BinFeatures --> EndUser["• End-user messages"]

    style Project fill:#4da6ff,stroke:#0066cc,color:white
    style CrateType fill:#ffa64d,stroke:#cc7a30,color:white
    style LibCrate fill:#4dbb5f,stroke:#36873f,color:white
    style BinCrate fill:#d94dbb,stroke:#a3378a,color:white
```

## 📚 LIBRARY CRATE ERROR HANDLING (thiserror)

### Error Definition Pattern

```rust
// lib_crate/src/errors.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MyLibError {
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("File not found: {path}")]
    FileNotFound { path: String },

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Network error")]
    Network(#[from] reqwest::Error),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Internal error: {0}")]
    Internal(String),
}

// Additional result type alias for convenience
pub type Result<T> = std::result::Result<T, MyLibError>;

// Error construction helpers
impl MyLibError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub fn file_not_found(path: impl Into<String>) -> Self {
        Self::FileNotFound {
            path: path.into(),
        }
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}
```

### Usage in Library Functions

```rust
// lib_crate/src/lib.rs
use crate::errors::{MyLibError, Result};

pub fn process_file(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(MyLibError::invalid_input("Path cannot be empty"));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|_| MyLibError::file_not_found(path))?;

    if content.is_empty() {
        return Err(MyLibError::invalid_input("File is empty"));
    }

    Ok(content.to_uppercase())
}

pub fn parse_config(data: &str) -> Result<Config> {
    // The #[from] attribute automatically converts serde_json::Error
    let config: Config = serde_json::from_str(data)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_path_error() {
        let result = process_file("");
        assert!(matches!(result, Err(MyLibError::InvalidInput { .. })));
    }

    #[test]
    fn test_file_not_found_error() {
        let result = process_file("nonexistent.txt");
        assert!(matches!(result, Err(MyLibError::FileNotFound { .. })));
    }
}
```

## 🏃 BINARY CRATE ERROR HANDLING (anyhow)

### Error Definition Pattern

```rust
// bin_crate/src/errors.rs
use anyhow::{Context, Result};
use thiserror::Error;

// Define application-specific errors that need structure
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("User error: {message}")]
    User { message: String },

    #[error("System error: {message}")]
    System { message: String },
}

// Helper functions for common error patterns
pub fn config_error(message: impl Into<String>) -> AppError {
    AppError::Config {
        message: message.into(),
    }
}

pub fn user_error(message: impl Into<String>) -> AppError {
    AppError::User {
        message: message.into(),
    }
}

pub fn system_error(message: impl Into<String>) -> AppError {
    AppError::System {
        message: message.into(),
    }
}

// Type alias for the main Result type
pub type AppResult<T> = Result<T>;
```

### Usage in Binary Application

```rust
// bin_crate/src/main.rs
use anyhow::{Context, Result, bail, ensure};
use crate::errors::{AppResult, user_error, config_error};

fn main() -> Result<()> {
    let config = load_config()
        .context("Failed to load application configuration")?;

    let result = process_data(&config)
        .context("Failed to process data")?;

    save_results(&result)
        .context("Failed to save results")?;

    println!("Processing completed successfully");
    Ok(())
}

fn load_config() -> AppResult<Config> {
    let config_path = std::env::var("CONFIG_PATH")
        .context("CONFIG_PATH environment variable not set")?;

    ensure!(!config_path.is_empty(), config_error("Config path is empty"));

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;

    let config: Config = toml::from_str(&content)
        .context("Failed to parse config file as TOML")?;

    Ok(config)
}

fn process_data(config: &Config) -> AppResult<ProcessResult> {
    if config.input_files.is_empty() {
        bail!(user_error("No input files specified"));
    }

    let mut results = Vec::new();

    for file_path in &config.input_files {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read input file: {}", file_path))?;

        let processed = process_file_content(&content)
            .with_context(|| format!("Failed to process file: {}", file_path))?;

        results.push(processed);
    }

    Ok(ProcessResult { results })
}

fn process_file_content(content: &str) -> Result<String> {
    ensure!(!content.is_empty(), "File content is empty");

    // Complex processing logic that might fail
    let processed = content
        .lines()
        .map(|line| process_line(line))
        .collect::<Result<Vec<_>>>()?
        .join("\n");

    Ok(processed)
}

fn process_line(line: &str) -> Result<String> {
    if line.trim().is_empty() {
        return Ok(String::new());
    }

    // Some processing that might fail
    Ok(line.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_line_success() {
        let result = process_line("hello world").unwrap();
        assert_eq!(result, "HELLO WORLD");
    }

    #[test]
    fn test_process_empty_line() {
        let result = process_line("").unwrap();
        assert_eq!(result, "");
    }
}
```

## 🔄 ERROR HANDLING WORKFLOW

```mermaid
sequenceDiagram
    participant Code as Application Code
    participant Lib as Library
    participant Error as Error Handler
    participant User as End User

    Code->>Lib: Call library function
    Lib->>Lib: Process request

    alt Success Case
        Lib->>Code: Return Ok(result)
        Code->>User: Success response
    else Library Error (thiserror)
        Lib->>Code: Return Err(LibError)
        Code->>Error: Convert to anyhow
        Error->>Error: Add context
        Error->>User: Formatted error message
    else System Error
        Lib->>Code: Return Err(SystemError)
        Code->>Error: Add application context
        Error->>User: User-friendly message
    end
```

## 📋 ERROR CATEGORIES AND HANDLING

```mermaid
graph TD
    Error["Error Occurred"] --> Category["Categorize Error"]

    Category --> Recoverable["Recoverable<br>Error"]
    Category --> Fatal["Fatal<br>Error"]
    Category --> User["User<br>Error"]
    Category --> System["System<br>Error"]

    Recoverable --> Retry["Implement<br>Retry Logic"]
    Recoverable --> Fallback["Provide<br>Fallback"]

    Fatal --> Cleanup["Cleanup<br>Resources"]
    Fatal --> Exit["Exit<br>Gracefully"]

    User --> Validate["Validate<br>Input"]
    User --> Feedback["Provide<br>Feedback"]

    System --> Log["Log<br>Error"]
    System --> Alert["Alert<br>Operators"]

    style Error fill:#4da6ff,stroke:#0066cc,color:white
    style Recoverable fill:#4dbb5f,stroke:#36873f,color:white
    style Fatal fill:#d94dbb,stroke:#a3378a,color:white
    style User fill:#ffa64d,stroke:#cc7a30,color:white
    style System fill:#4dbbbb,stroke:#368787,color:white
```

## 🛠️ ERROR HANDLING PATTERNS

### Pattern 1: Early Return with Context

```rust
fn complex_operation(input: &str) -> Result<ProcessedData> {
    let validated = validate_input(input)
        .context("Input validation failed")?;

    let parsed = parse_data(&validated)
        .context("Failed to parse input data")?;

    let transformed = transform_data(parsed)
        .context("Data transformation failed")?;

    let result = finalize_data(transformed)
        .context("Failed to finalize processing")?;

    Ok(result)
}
```

### Pattern 2: Error Mapping

```rust
fn convert_external_error() -> Result<String> {
    external_library::fetch_data()
        .map_err(|e| anyhow::anyhow!("External service failed: {}", e))?;

    Ok("success".to_string())
}
```

### Pattern 3: Conditional Error Handling

```rust
fn conditional_processing(config: &Config) -> Result<()> {
    if config.strict_mode {
        process_strictly()
            .context("Strict processing failed")?;
    } else {
        match process_leniently() {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Warning: Lenient processing failed: {}", e);
                default_result()
            }
        }
    }

    Ok(())
}
```

## 📝 ERROR HANDLING CHECKLIST

```markdown
## Error Handling Verification

### Library Crates (thiserror)
- [ ] All errors defined in centralized errors.rs
- [ ] Error types derive Error, Debug
- [ ] Meaningful error messages with #[error]
- [ ] Proper use of #[from] for conversions
- [ ] Helper constructors for complex errors
- [ ] Result type alias defined
- [ ] Comprehensive error documentation

### Binary Crates (anyhow)
- [ ] anyhow::Result used consistently
- [ ] Context added to all error chains
- [ ] User-friendly error messages
- [ ] Proper cleanup on fatal errors
- [ ] Structured errors for app-specific cases
- [ ] Graceful error handling in main()

### General
- [ ] No unwrap() or expect() in production code
- [ ] Errors properly propagated
- [ ] Error tests included
- [ ] Error logging implemented
- [ ] Recovery strategies defined
```

## 🚨 ANTI-PATTERNS TO AVOID

### ❌ Don't Do This

```rust
// ❌ Using unwrap in production code
let value = risky_operation().unwrap();

// ❌ Ignoring errors
let _ = might_fail();

// ❌ Generic error messages
return Err("Something went wrong".into());

// ❌ Mixing error handling approaches
fn mixed_errors() -> Result<(), Box<dyn std::error::Error>> {
    // Inconsistent error handling
}

// ❌ Not providing context
let data = load_file(path)?; // No context about which file failed
```

### ✅ Do This Instead

```rust
// ✅ Proper error handling with context
let value = risky_operation()
    .context("Failed to perform risky operation")?;

// ✅ Handle or propagate errors explicitly
if let Err(e) = might_fail() {
    eprintln!("Operation failed: {}", e);
    return Err(e);
}

// ✅ Specific error messages
return Err(MyError::InvalidInput {
    field: "email".to_string(),
    value: input.to_string(),
});

// ✅ Consistent error handling approach
fn consistent_errors() -> Result<(), MyAppError> {
    // Consistent with project patterns
}

// ✅ Rich context for debugging
let data = load_file(path)
    .with_context(|| format!("Failed to load config file: {}", path))?;
```

This error handling strategy ensures robust, maintainable error management across your Rust project while following industry best practices.

---
description:
globs:
alwaysApply: false
---
# 🧪 RUST TESTING STANDARDS

> **TL;DR:** Comprehensive testing guidelines for Rust projects covering unit tests, integration tests, property testing, benchmarks, and CI integration with best practices for test organization and coverage.

## 🔍 TESTING STRATEGY SELECTION

```mermaid
graph TD
    Start["Testing Requirements"] --> Strategy{"Testing Strategy?"}

    Strategy -->|"Unit Testing"| Unit["Unit Tests"]
    Strategy -->|"Integration Testing"| Integration["Integration Tests"]
    Strategy -->|"Property Testing"| Property["Property Testing"]
    Strategy -->|"Benchmarking"| Benchmark["Performance Benchmarks"]
    Strategy -->|"End-to-End Testing"| E2E["E2E Tests"]

    Unit --> UnitFeatures["Unit Test Features:"]
    Integration --> IntegrationFeatures["Integration Features:"]
    Property --> PropertyFeatures["Property Features:"]
    Benchmark --> BenchmarkFeatures["Benchmark Features:"]
    E2E --> E2EFeatures["E2E Features:"]

    UnitFeatures --> UnitItems["• Individual function testing<br>• Mock dependencies<br>• Fast execution<br>• High coverage"]
    IntegrationFeatures --> IntegrationItems["• Multi-module testing<br>• Real dependencies<br>• Realistic scenarios<br>• API testing"]
    PropertyFeatures --> PropertyItems["• Random input testing<br>• Edge case discovery<br>• Invariant verification<br>• Fuzzing"]
    BenchmarkFeatures --> BenchmarkItems["• Performance regression<br>• Memory usage tracking<br>• Throughput measurement<br>• Optimization validation"]
    E2EFeatures --> E2EItems["• Full system testing<br>• User workflow validation<br>• External service mocking<br>• Production-like environment"]

    UnitItems --> Tools["Testing Tools"]
    IntegrationItems --> Tools
    PropertyItems --> Tools
    BenchmarkItems --> Tools
    E2EItems --> Tools

    Tools --> MockTool["Mocking: mockall"]
    Tools --> PropertyTool["Property: proptest"]
    Tools --> BenchTool["Benchmarks: criterion"]
    Tools --> WebTool["Web Testing: axum-test"]
    Tools --> HttpTool["HTTP Mocking: wiremock"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Strategy fill:#ffa64d,stroke:#cc7a30,color:white
    style Unit fill:#4dbb5f,stroke:#36873f,color:white
    style Integration fill:#d94dbbb,stroke:#a3378a,color:white
    style Property fill:#9f4dbb,stroke:#7a3787,color:white
    style Benchmark fill:#bb4d4d,stroke:#873636,color:white
    style E2E fill:#bbbb4d,stroke:#878736,color:white
```

## 🏗️ CARGO TEST ORGANIZATION

### Project Structure for Testing

```rust
// Project structure with comprehensive testing
my_project/
├── Cargo.toml
├── src/
│   ├── lib.rs           // Library root with unit tests
│   ├── main.rs          // Binary entry point
│   ├── user/
│   │   ├── mod.rs       // Module with inline unit tests
│   │   ├── service.rs   // Service with unit tests
│   │   └── repository.rs // Repository with unit tests
│   └── product/
│       ├── mod.rs
│       └── catalog.rs
├── tests/               // Integration tests directory
│   ├── integration_test.rs
│   ├── api_test.rs
│   └── common/          // Shared test utilities
│       └── mod.rs
└── benches/             // Benchmark tests
    ├── user_benchmarks.rs
    └── product_benchmarks.rs
```

### Unit Test Configuration

```rust
// src/user/service.rs
use crate::user::{User, UserRepository, UserError};
use mockall::predicate::*;

pub struct UserService<R: UserRepository> {
    repository: R,
}

impl<R: UserRepository> UserService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn create_user(&self, user: User) -> Result<User, UserError> {
        // Validate user data
        if user.email.is_empty() {
            return Err(UserError::InvalidInput("Email cannot be empty".to_string()));
        }

        // Save to repository
        self.repository.save(user).await
    }

    pub async fn find_user(&self, id: &str) -> Result<Option<User>, UserError> {
        if id.is_empty() {
            return Err(UserError::InvalidInput("ID cannot be empty".to_string()));
        }

        self.repository.find_by_id(id).await
    }
}

// ✅ Unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    // Mock the repository trait
    mock! {
        TestUserRepository {}

        #[async_trait::async_trait]
        impl UserRepository for TestUserRepository {
            async fn save(&self, user: User) -> Result<User, UserError>;
            async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserError>;
        }
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let mut mock_repo = MockTestUserRepository::new();
        let user = User {
            id: "123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
        };

        mock_repo
            .expect_save()
            .with(eq(user.clone()))
            .times(1)
            .returning(|user| Ok(user));

        let service = UserService::new(mock_repo);
        let result = service.create_user(user.clone()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user);
    }

    #[tokio::test]
    async fn test_create_user_empty_email_fails() {
        let mock_repo = MockTestUserRepository::new();
        let user = User {
            id: "123".to_string(),
            email: "".to_string(),  // Empty email
            name: "Test User".to_string(),
        };

        let service = UserService::new(mock_repo);
        let result = service.create_user(user).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), UserError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn test_find_user_success() {
        let mut mock_repo = MockTestUserRepository::new();
        let expected_user = User {
            id: "123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
        };

        mock_repo
            .expect_find_by_id()
            .with(eq("123"))
            .times(1)
            .returning(move |_| Ok(Some(expected_user.clone())));

        let service = UserService::new(mock_repo);
        let result = service.find_user("123").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_find_user_empty_id_fails() {
        let mock_repo = MockTestUserRepository::new();
        let service = UserService::new(mock_repo);

        let result = service.find_user("").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), UserError::InvalidInput(_)));
    }
}
```

## 🔗 INTEGRATION TESTING

### Integration Test Structure

```rust
// tests/integration_test.rs
use my_project::{User, UserService, PostgresUserRepository};
use testcontainers::{clients::Cli, images::postgres::Postgres, Container};
use sqlx::PgPool;

struct TestContext {
    pool: PgPool,
    _container: Container<'static, Postgres>,
}

impl TestContext {
    async fn new() -> Self {
        let docker = Cli::default();
        let container = docker.run(Postgres::default());
        let host_port = container.get_host_port_ipv4(5432);

        let database_url = format!("postgres://postgres:password@localhost:{}/test", host_port);
        let pool = PgPool::connect(&database_url).await.unwrap();

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        Self {
            pool,
            _container: container,
        }
    }
}

#[tokio::test]
async fn test_user_service_integration() {
    let ctx = TestContext::new().await;
    let repository = PostgresUserRepository::new(ctx.pool.clone());
    let service = UserService::new(repository);

    let user = User {
        id: "integration-test-123".to_string(),
        email: "integration@example.com".to_string(),
        name: "Integration User".to_string(),
    };

    // Test create
    let created_user = service.create_user(user.clone()).await.unwrap();
    assert_eq!(created_user.email, user.email);

    // Test find
    let found_user = service.find_user(&user.id).await.unwrap();
    assert!(found_user.is_some());
    assert_eq!(found_user.unwrap().id, user.id);
}

#[tokio::test]
async fn test_duplicate_user_creation_fails() {
    let ctx = TestContext::new().await;
    let repository = PostgresUserRepository::new(ctx.pool.clone());
    let service = UserService::new(repository);

    let user = User {
        id: "duplicate-test-123".to_string(),
        email: "duplicate@example.com".to_string(),
        name: "Duplicate User".to_string(),
    };

    // First creation should succeed
    service.create_user(user.clone()).await.unwrap();

    // Second creation should fail
    let result = service.create_user(user).await;
    assert!(result.is_err());
}
```

## 🧬 PROPERTY TESTING WITH PROPTEST

### Property Test Configuration

```rust
// Cargo.toml
[dev-dependencies]
proptest = "1.5"

// src/user/validation.rs
use proptest::prelude::*;

pub fn validate_email(email: &str) -> bool {
    email.contains('@') && email.len() > 3 && email.len() < 255
}

pub fn validate_username(username: &str) -> bool {
    username.len() >= 3 && username.len() <= 50 && username.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_valid_email_always_contains_at(email in r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
            prop_assert!(validate_email(&email));
        }

        #[test]
        fn test_invalid_email_without_at(email in r"[a-zA-Z0-9._%+-]+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
            prop_assert!(!validate_email(&email));
        }

        #[test]
        fn test_username_length_bounds(username in r"[a-zA-Z0-9_]{3,50}") {
            prop_assert!(validate_username(&username));
        }

        #[test]
        fn test_username_too_short(username in r"[a-zA-Z0-9_]{1,2}") {
            prop_assert!(!validate_username(&username));
        }

        #[test]
        fn test_username_too_long(username in r"[a-zA-Z0-9_]{51,100}") {
            prop_assert!(!validate_username(&username));
        }

        #[test]
        fn test_username_invalid_chars(username in r"[a-zA-Z0-9_]*[^a-zA-Z0-9_]+[a-zA-Z0-9_]*") {
            prop_assume!(!username.is_empty());
            prop_assert!(!validate_username(&username));
        }
    }

    // Custom strategy for generating valid users
    fn valid_user_strategy() -> impl Strategy<Value = User> {
        (
            r"user[0-9]{1,6}",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            r"[A-Z][a-z]{2,20} [A-Z][a-z]{2,20}",
        )
            .prop_map(|(id, email, name)| User { id, email, name })
    }

    proptest! {
        #[test]
        fn test_user_serialization_roundtrip(user in valid_user_strategy()) {
            let json = serde_json::to_string(&user).unwrap();
            let deserialized: User = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(user, deserialized);
        }
    }
}
```

## 🚀 PERFORMANCE BENCHMARKING

### Criterion Benchmark Setup

```rust
// Cargo.toml
[[bench]]
name = "user_benchmarks"
harness = false

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

// benches/user_benchmarks.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use my_project::{User, UserService, InMemoryUserRepository};

fn create_user_benchmark(c: &mut Criterion) {
    let repository = InMemoryUserRepository::new();
    let service = UserService::new(repository);

    c.bench_function("create_user", |b| {
        b.iter(|| {
            let user = User {
                id: format!("bench-{}", fastrand::u64(..)),
                email: "bench@example.com".to_string(),
                name: "Benchmark User".to_string(),
            };

            black_box(service.create_user(user))
        })
    });
}

fn find_user_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_user");

    for size in [100, 1000, 10000].iter() {
        let repository = InMemoryUserRepository::new();
        let service = UserService::new(repository);

        // Pre-populate with users
        for i in 0..*size {
            let user = User {
                id: format!("user-{}", i),
                email: format!("user{}@example.com", i),
                name: format!("User {}", i),
            };
            service.create_user(user).unwrap();
        }

        group.bench_with_input(BenchmarkId::new("size", size), size, |b, &size| {
            b.iter(|| {
                let user_id = format!("user-{}", fastrand::usize(0..size));
                black_box(service.find_user(&user_id))
            })
        });
    }
    group.finish();
}

criterion_group!(benches, create_user_benchmark, find_user_benchmark);
criterion_main!(benches);
```

## 🌐 WEB API TESTING

### Axum Test Integration

```rust
// Cargo.toml
[dev-dependencies]
axum-test = "16"
wiremock = "0.6"

// tests/api_test.rs
use axum_test::TestServer;
use my_project::{create_app, AppState};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_create_user_api() {
    let app_state = AppState::new_test();
    let app = create_app(app_state);
    let server = TestServer::new(app).unwrap();

    let user_data = serde_json::json!({
        "email": "api@example.com",
        "name": "API User"
    });

    let response = server
        .post("/users")
        .json(&user_data)
        .await;

    response.assert_status_created();
    response.assert_json(&serde_json::json!({
        "id": response.json::<serde_json::Value>()["id"],
        "email": "api@example.com",
        "name": "API User"
    }));
}

#[tokio::test]
async fn test_external_service_integration() {
    // Mock external service
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/external/users/123"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(&serde_json::json!({
                "id": "123",
                "verified": true
            })))
        .mount(&mock_server)
        .await;

    let app_state = AppState::new_test_with_external_url(&mock_server.uri());
    let app = create_app(app_state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/users/123/verification")
        .await;

    response.assert_status_ok();
    response.assert_json(&serde_json::json!({
        "verified": true
    }));
}
```

## 📊 COVERAGE AND CI INTEGRATION

### Coverage Configuration

```bash
# Install tarpaulin for coverage
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out html --output-dir coverage

# CI-friendly coverage
cargo tarpaulin --out xml --output-dir coverage
```

### GitHub Actions Configuration

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: rustfmt, clippy

    - name: Cache dependencies
      uses: actions/cache@v4
      with:
        path: |
          ~/.cargo/bin/
          ~/.cargo/registry/index/
          ~/.cargo/registry/cache/
          ~/.cargo/git/db/
          target/
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Check formatting
      run: cargo fmt --all -- --check

    - name: Clippy
      run: cargo clippy --all-targets --all-features -- -D warnings

    - name: Unit Tests
      run: cargo test --lib
      env:
        DATABASE_URL: postgres://postgres:password@localhost:5432/test

    - name: Integration Tests
      run: cargo test --test '*'
      env:
        DATABASE_URL: postgres://postgres:password@localhost:5432/test

    - name: Doc Tests
      run: cargo test --doc

    - name: Benchmarks (check only)
      run: cargo bench --no-run

  coverage:
    runs-on: ubuntu-latest
    needs: test

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable

    - name: Install tarpaulin
      run: cargo install cargo-tarpaulin

    - name: Generate coverage
      run: cargo tarpaulin --out xml --output-dir coverage
      env:
        DATABASE_URL: postgres://postgres:password@localhost:5432/test

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v4
      with:
        file: coverage/cobertura.xml
        fail_ci_if_error: true
```

## ✅ TESTING CHECKLIST

```markdown
### Testing Completeness Verification
- [ ] Unit tests for all public functions
- [ ] Unit tests use mocking for external dependencies
- [ ] Integration tests cover realistic scenarios
- [ ] Property tests validate invariants
- [ ] Benchmarks track performance regressions
- [ ] Test coverage > 80% for core modules
- [ ] Tests run in CI/CD pipeline
- [ ] No `unwrap()` or `expect()` in test code
- [ ] Test data is deterministic or properly seeded
- [ ] Async tests use `#[tokio::test]`
- [ ] Web API tests cover error cases
- [ ] External services are properly mocked
- [ ] Database tests use transactions or containers
- [ ] Tests are organized by functionality
- [ ] Test names clearly describe scenarios
```

## 📚 TESTING DEPENDENCIES

### Essential Testing Crates

```toml
[dev-dependencies]
# Core testing
tokio-test = "0.4"          # Async testing utilities

# Mocking
mockall = "0.13"            # Mock generation
wiremock = "0.6"           # HTTP service mocking

# Property testing
proptest = "1.5"           # Property-based testing

# Benchmarking
criterion = { version = "0.5", features = ["html_reports"] }

# Web testing
axum-test = "16"           # Axum application testing

# Database testing
testcontainers = "0.21"    # Docker containers for tests
sqlx = { version = "0.8", features = ["testing"] }

# Utilities
tempfile = "3.13"          # Temporary files for tests
serde_json = "1.0"         # JSON serialization for tests
```

This comprehensive testing standard ensures robust, reliable Rust applications with thorough test coverage and quality assurance.
