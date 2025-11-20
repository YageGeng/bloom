use serde::{Deserialize, Serialize};

pub type Result<T> = color_eyre::Result<T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    pub uuid: Option<String>,
    pub refresh_token: Option<String>,
}

impl Account {
    pub fn anonymous(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            uuid: None,
            refresh_token: None,
        }
    }
}

pub fn placeholder_login_flow() -> Result<Account> {
    tracing::warn!("auth module is stubbed; real login flow to be added in M3");
    Ok(Account::anonymous("Player"))
}
