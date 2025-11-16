use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proto::DeviceFlowStartResponse;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DeviceFlowConfig {
    pub device_code_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: String,
    pub audience: Option<String>,
}

#[derive(Clone)]
pub struct DeviceFlowManager {
    client: Client,
    config: DeviceFlowConfig,
    sessions: Arc<Mutex<HashMap<String, DeviceFlowState>>>,
}

#[derive(Debug, Error)]
pub enum DeviceFlowError {
    #[error("unknown device authorization flow")]
    NotFound,
    #[error("identity provider rejected device flow: {0}")]
    Provider(String),
    #[error("device flow misconfigured: {0}")]
    Configuration(String),
}

#[derive(Debug)]
pub enum DeviceFlowOutcome {
    Pending {
        interval: u64,
    },
    Authorized {
        access_token: String,
    },
    Denied {
        error: String,
        description: Option<String>,
    },
    Expired,
}

#[derive(Debug)]
struct DeviceFlowState {
    device_code: String,
    expires_at: Instant,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct ProviderDeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProviderTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    _expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ProviderTokenError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

impl DeviceFlowManager {
    pub fn new(config: DeviceFlowConfig) -> Result<Self, DeviceFlowError> {
        let client = Client::builder().build().map_err(|err| {
            DeviceFlowError::Configuration(format!("failed to build HTTP client: {err}"))
        })?;
        Ok(Self {
            client,
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn start_flow(&self) -> Result<DeviceFlowStartResponse, DeviceFlowError> {
        let mut payload = vec![
            ("client_id".to_string(), self.config.client_id.clone()),
            ("scope".to_string(), self.config.scope.clone()),
        ];
        if let Some(audience) = &self.config.audience {
            payload.push(("audience".into(), audience.clone()));
        }

        let provider_resp: ProviderDeviceResponse = self
            .client
            .post(&self.config.device_code_url)
            .form(&payload)
            .send()
            .await
            .map_err(|err| {
                DeviceFlowError::Provider(format!("failed to request device code: {err}"))
            })?
            .error_for_status()
            .map_err(|err| {
                DeviceFlowError::Provider(format!(
                    "device authorization endpoint returned an error: {err}"
                ))
            })?
            .json()
            .await
            .map_err(|err| {
                DeviceFlowError::Provider(format!("invalid device authorization response: {err}"))
            })?;

        let flow_id = Uuid::new_v4().to_string();
        let interval = provider_resp.interval.unwrap_or(5).max(1);
        let expires_at = Instant::now() + Duration::from_secs(provider_resp.expires_in);
        let state = DeviceFlowState {
            device_code: provider_resp.device_code.clone(),
            expires_at,
            interval,
        };
        self.sessions.lock().await.insert(flow_id.clone(), state);

        Ok(DeviceFlowStartResponse {
            flow_id,
            user_code: provider_resp.user_code,
            verification_uri: provider_resp.verification_uri,
            verification_uri_complete: provider_resp.verification_uri_complete,
            expires_in: provider_resp.expires_in,
            interval,
            message: provider_resp.message,
        })
    }

    pub async fn poll_flow(&self, flow_id: &str) -> Result<DeviceFlowOutcome, DeviceFlowError> {
        let (device_code, interval) = {
            let sessions = self.sessions.lock().await;
            let state = sessions.get(flow_id).ok_or(DeviceFlowError::NotFound)?;

            if Instant::now() >= state.expires_at {
                drop(sessions);
                self.sessions.lock().await.remove(flow_id);
                return Ok(DeviceFlowOutcome::Expired);
            }

            (state.device_code.clone(), state.interval)
        };

        let mut payload = vec![
            (
                "grant_type".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code".to_string(), device_code),
            ("client_id".to_string(), self.config.client_id.clone()),
        ];
        if let Some(secret) = &self.config.client_secret {
            payload.push(("client_secret".into(), secret.clone()));
        }

        let response = self
            .client
            .post(&self.config.token_url)
            .form(&payload)
            .send()
            .await
            .map_err(|err| {
                DeviceFlowError::Provider(format!("failed to poll token endpoint: {err}"))
            })?;

        if response.status().is_success() {
            let token: ProviderTokenResponse = response.json().await.map_err(|err| {
                DeviceFlowError::Provider(format!("invalid token response: {err}"))
            })?;

            if !token.token_type.eq_ignore_ascii_case("bearer") {
                return Err(DeviceFlowError::Provider(format!(
                    "unsupported token type {}",
                    token.token_type
                )));
            }

            self.sessions.lock().await.remove(flow_id);
            return Ok(DeviceFlowOutcome::Authorized {
                access_token: token.access_token,
            });
        }

        let error: ProviderTokenError = response
            .json()
            .await
            .map_err(|err| DeviceFlowError::Provider(format!("invalid error payload: {err}")))?;

        match error.error.as_str() {
            "authorization_pending" => Ok(DeviceFlowOutcome::Pending { interval }),
            "slow_down" => {
                let new_interval = interval + 5;
                if let Some(state) = self.sessions.lock().await.get_mut(flow_id) {
                    state.interval = new_interval;
                }
                Ok(DeviceFlowOutcome::Pending {
                    interval: new_interval,
                })
            }
            "access_denied" => {
                self.sessions.lock().await.remove(flow_id);
                Ok(DeviceFlowOutcome::Denied {
                    error: error.error,
                    description: error.error_description,
                })
            }
            "expired_token" => {
                self.sessions.lock().await.remove(flow_id);
                Ok(DeviceFlowOutcome::Expired)
            }
            other => Err(DeviceFlowError::Provider(format!(
                "token endpoint returned {other}: {}",
                error.error_description.unwrap_or_default()
            ))),
        }
    }
}
