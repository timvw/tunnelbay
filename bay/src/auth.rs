use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result as AnyResult;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub subject: String,
    pub email: Option<String>,
    #[allow(dead_code)]
    pub scopes: Vec<String>,
}

impl AuthContext {
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".into(),
            email: None,
            scopes: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct AuthManager {
    mode: Arc<AuthMode>,
}

impl AuthManager {
    pub fn disabled() -> Self {
        Self {
            mode: Arc::new(AuthMode::Disabled),
        }
    }

    pub fn oidc(config: OidcConfig) -> AnyResult<Self> {
        let authenticator = OidcAuthenticator::new(config)?;
        Ok(Self {
            mode: Arc::new(AuthMode::Oidc(authenticator)),
        })
    }

    pub async fn authenticate(&self, header_value: Option<&str>) -> Result<AuthContext, AuthError> {
        match self.mode.as_ref() {
            AuthMode::Disabled => Ok(AuthContext::anonymous()),
            AuthMode::Oidc(authenticator) => {
                let token = header_value
                    .and_then(extract_bearer_token)
                    .ok_or(AuthError::MissingCredentials)?;
                authenticator.authenticate(token).await
            }
        }
    }
}

enum AuthMode {
    Disabled,
    Oidc(OidcAuthenticator),
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub jwks_url: String,
    pub audience: Option<String>,
    pub issuer: Option<String>,
    pub required_scopes: Vec<String>,
    pub cache_ttl: Duration,
}

struct OidcAuthenticator {
    client: Client,
    jwks_url: String,
    audience: Option<String>,
    issuer: Option<String>,
    required_scopes: Vec<String>,
    cache_ttl: Duration,
    cache: RwLock<Option<CachedJwks>>,
}

struct CachedJwks {
    set: Arc<JwkSet>,
    fetched_at: Instant,
}

impl OidcAuthenticator {
    fn new(config: OidcConfig) -> AnyResult<Self> {
        let client = Client::builder().build()?;
        Ok(Self {
            client,
            jwks_url: config.jwks_url,
            audience: config.audience,
            issuer: config.issuer,
            required_scopes: config.required_scopes,
            cache_ttl: config.cache_ttl,
            cache: RwLock::new(None),
        })
    }

    async fn authenticate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let header = decode_header(token)
            .map_err(|err| AuthError::InvalidToken(format!("invalid token header: {err}")))?;
        let algorithm = header.alg;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("token missing kid header".into()))?;

        let jwk_set = self.get_jwk_set().await?;
        let jwk = jwk_set.find(&kid).ok_or_else(|| {
            AuthError::InvalidToken(format!("no signing key available for kid {kid}"))
        })?;

        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|err| {
            AuthError::Configuration(format!(
                "unable to construct decoding key from jwk {kid}: {err}"
            ))
        })?;

        let mut validation = Validation::new(algorithm);
        validation.validate_aud = false;
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|err| AuthError::InvalidToken(format!("failed to validate token: {err}")))?;

        self.validate_claims(&token_data.claims)?;
        Ok(AuthContext {
            subject: token_data.claims.sub,
            email: token_data.claims.email,
            scopes: parse_scope_list(token_data.claims.scope.as_deref()),
        })
    }

    async fn get_jwk_set(&self) -> Result<Arc<JwkSet>, AuthError> {
        {
            let guard = self.cache.read().await;
            if let Some(cache) = guard.as_ref() {
                if cache.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cache.set.clone());
                }
            }
        }

        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|err| {
                AuthError::Configuration(format!(
                    "failed to fetch JWKS from {}: {err}",
                    self.jwks_url
                ))
            })?
            .error_for_status()
            .map_err(|err| {
                AuthError::Configuration(format!(
                    "received error from JWKS endpoint {}: {err}",
                    self.jwks_url
                ))
            })?;

        let jwk_set: JwkSet = response
            .json()
            .await
            .map_err(|err| AuthError::Configuration(format!("invalid JWKS payload: {err}")))?;

        let jwk_set = Arc::new(jwk_set);
        let mut guard = self.cache.write().await;
        *guard = Some(CachedJwks {
            set: jwk_set.clone(),
            fetched_at: Instant::now(),
        });
        Ok(jwk_set)
    }

    fn validate_claims(&self, claims: &TokenClaims) -> Result<(), AuthError> {
        if let Some(expected_issuer) = &self.issuer {
            if !claims
                .iss
                .as_ref()
                .map(|iss| iss == expected_issuer)
                .unwrap_or(false)
            {
                return Err(AuthError::InvalidToken(format!(
                    "issuer mismatch: expected {expected_issuer}"
                )));
            }
        }

        if let Some(expected_audience) = &self.audience {
            if !claims
                .aud
                .as_ref()
                .map(|aud| aud.contains(expected_audience))
                .unwrap_or(false)
            {
                return Err(AuthError::InvalidToken(format!(
                    "audience mismatch: expected {expected_audience}"
                )));
            }
        }

        if !self.required_scopes.is_empty() {
            let scopes = parse_scope_list(claims.scope.as_deref());
            for required in &self.required_scopes {
                if !scope_satisfied(required, &scopes, claims) {
                    return Err(AuthError::Forbidden(format!(
                        "missing scopes: {:?}",
                        self.required_scopes
                    )));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing Authorization bearer token")]
    MissingCredentials,
    #[error("invalid authorization token: {0}")]
    InvalidToken(String),
    #[error("insufficient scope: {0}")]
    Forbidden(String),
    #[error("authorization subsystem misconfigured: {0}")]
    Configuration(String),
}

#[derive(Debug, Deserialize, Default)]
struct TokenClaims {
    sub: String,
    #[serde(default)]
    aud: Option<Audience>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    register: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(value) => value == expected,
            Audience::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }
}

fn extract_bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    }
}

fn parse_scope_list(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(' ')
            .flat_map(|part| part.split(','))
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .map(|scope| scope.to_string())
            .collect()
    })
    .unwrap_or_default()
}

fn scope_satisfied(required: &str, granted: &[String], claims: &TokenClaims) -> bool {
    if granted.iter().any(|scope| scope == required) {
        return true;
    }

    match required {
        "register:buoy" => claims.register.unwrap_or(false),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::{extract_bearer_token, parse_scope_list, scope_satisfied, TokenClaims};

    #[test]
    fn parses_bearer_tokens() {
        assert_eq!(extract_bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer_token("bearer  token123"), Some("token123"));
        assert!(extract_bearer_token("Basic abc").is_none());
        assert!(extract_bearer_token("Bearer   ").is_none());
    }

    #[test]
    fn splits_scope_strings() {
        let scopes = parse_scope_list(Some("read:all write:buoys"));
        assert_eq!(scopes, vec!["read:all", "write:buoys"]);
        assert!(parse_scope_list(None).is_empty());
    }

    #[test]
    fn checks_required_scopes() {
        let granted: Vec<String> = vec!["read".into(), "write".into()];
        assert!(scope_satisfied("read", &granted, &TokenClaims::default()));
        assert!(!scope_satisfied("admin", &granted, &TokenClaims::default()));
    }
}
