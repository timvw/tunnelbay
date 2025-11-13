use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};

mod auth;

use auth::{AuthContext, AuthError, AuthManager, OidcConfig};

use anyhow::{Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    extract::{ConnectInfo, State},
    http::{header::HeaderName, header::HeaderValue, HeaderMap, Request, Response, StatusCode},
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use axum_extra::extract::Host;
use base64::{engine::general_purpose, Engine as _};
use futures::{future, SinkExt, StreamExt};
use proto::{ClientToServer, Header, ServerToClient};
use rand::distr::{Alphanumeric, SampleString};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, Mutex, RwLock},
};
use uuid::Uuid;

const DEFAULT_DOMAIN: &str = "bay.localhost";
const DEFAULT_CONTROL_ADDR: &str = "0.0.0.0:7070";
const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:8080";
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

#[tokio::main]
async fn main() -> Result<()> {
    let settings = Settings::from_env()?;
    println!(
        "Starting TunnelBay with domain {} (HTTP {}, control {})",
        settings.domain, settings.http_addr, settings.control_addr
    );
    let state = Arc::new(AppState::new(
        settings.domain.clone(),
        settings.auth.clone(),
    ));

    let http_state = state.clone();
    let ctrl_state = state.clone();
    let http_addr = settings.http_addr.clone();
    let control_addr = settings.control_addr.clone();

    let http_task = tokio::spawn(async move {
        match run_http_server(http_state, http_addr).await {
            Ok(()) => eprintln!("HTTP server stopped"),
            Err(err) => eprintln!("HTTP server error: {err:?}"),
        }
    });

    let ctrl_task = tokio::spawn(async move {
        match run_control_server(ctrl_state, control_addr).await {
            Ok(()) => eprintln!("Control server stopped"),
            Err(err) => eprintln!("Control server error: {err:?}"),
        }
    });

    tokio::select! {
        _ = shutdown_signal() => {
            println!("Shutting down TunnelBay...");
        }
        res = http_task => {
            if let Err(err) = res {
                eprintln!("http task exited: {err:?}");
            }
        }
        res = ctrl_task => {
            if let Err(err) = res {
                eprintln!("control task exited: {err:?}");
            }
        }
    }

    Ok(())
}

async fn run_http_server(state: Arc<AppState>, addr: String) -> Result<()> {
    let app = Router::new().fallback(any(proxy_handler)).with_state(state);
    let listener = TcpListener::bind(&addr).await?;
    println!("HTTP endpoint listening on http://{addr}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

async fn run_control_server(state: Arc<AppState>, addr: String) -> Result<()> {
    let app = Router::new()
        .route("/control", get(control_ws_handler))
        .with_state(state);
    let listener = TcpListener::bind(&addr).await?;
    println!("Control endpoint listening on ws://{addr}/control");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(err) => {
            eprintln!(
                "Failed to install CTRL+C handler: {err}. Continuing without signal handling."
            );
            future::pending::<()>().await;
        }
    }
}

async fn proxy_handler(
    Host(host): Host,
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let slug = extract_slug(&host).ok_or(StatusCode::BAD_REQUEST)?;
    let tunnel = state.get_tunnel(slug).await.ok_or(StatusCode::NOT_FOUND)?;

    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;
    let bytes = to_bytes(body, MAX_REQUEST_BYTES)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());

    let request_id = Uuid::new_v4().to_string();
    let header_vec = header_map_to_proto(&headers);
    let encoded_body = general_purpose::STANDARD.encode(bytes);

    let message = ServerToClient::ForwardRequest {
        request_id: request_id.clone(),
        method: method.to_string(),
        path_and_query,
        headers: header_vec,
        body: encoded_body,
    };

    let (resp_tx, resp_rx) = oneshot::channel();
    tunnel
        .pending
        .lock()
        .await
        .insert(request_id.clone(), resp_tx);

    if tunnel.sender.send(message).await.is_err() {
        tunnel.pending.lock().await.remove(&request_id);
        state.remove_tunnel(slug).await;
        return Err(StatusCode::BAD_GATEWAY);
    }

    let response = tokio::time::timeout(Duration::from_secs(30), resp_rx)
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut response = convert_response(response)?;
    if let Ok(value) = HeaderValue::from_str(&tunnel.ip_address) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-forwarded-for"), value);
    }
    Ok(response)
}

async fn control_ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| addr.ip().to_string());
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    match state.authenticate(auth_header).await {
        Ok(auth_ctx) => {
            let state = state.clone();
            let ip = source_ip.clone();
            ws.on_upgrade(move |socket| {
                let state = state.clone();
                let auth_ctx = auth_ctx.clone();
                let ip = ip.clone();
                async move {
                    if let Err(err) = handle_buoy_ws(socket, state, ip, auth_ctx).await {
                        eprintln!("buoy connection closed: {err:?}");
                    }
                }
            })
        }
        Err(err) => {
            eprintln!("Rejected control connection from {source_ip}: {err}");
            match err {
                AuthError::MissingCredentials | AuthError::InvalidToken(_) => {
                    (StatusCode::UNAUTHORIZED, "Missing or invalid bearer token").into_response()
                }
                AuthError::Forbidden(_) => (
                    StatusCode::FORBIDDEN,
                    "The provided token is not allowed to register buoys",
                )
                    .into_response(),
                AuthError::Configuration(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication is temporarily unavailable",
                )
                    .into_response(),
            }
        }
    }
}

struct Settings {
    domain: String,
    control_addr: String,
    http_addr: String,
    auth: AuthManager,
}

impl Settings {
    fn from_env() -> Result<Self> {
        let domain = env::var("BAY_DOMAIN").unwrap_or_else(|_| DEFAULT_DOMAIN.to_string());
        let control_addr =
            env::var("BAY_CONTROL_ADDR").unwrap_or_else(|_| DEFAULT_CONTROL_ADDR.to_string());
        let http_addr = env::var("BAY_HTTP_ADDR").unwrap_or_else(|_| DEFAULT_HTTP_ADDR.to_string());
        let auth = auth_from_env()?;

        Ok(Self {
            domain,
            control_addr,
            http_addr,
            auth,
        })
    }
}

fn auth_from_env() -> Result<AuthManager> {
    let mode = env::var("BAY_AUTH_MODE").unwrap_or_else(|_| "disabled".into());
    match mode.to_lowercase().as_str() {
        "disabled" => Ok(AuthManager::disabled()),
        "oidc" => {
            let jwks_url = env::var("BAY_AUTH_JWKS_URL")
                .context("BAY_AUTH_JWKS_URL must be set when BAY_AUTH_MODE=oidc")?;
            let audience = env::var("BAY_AUTH_AUDIENCE").ok();
            let issuer = env::var("BAY_AUTH_ISSUER").ok();
            let required_scopes = env::var("BAY_AUTH_REQUIRED_SCOPES")
                .unwrap_or_default()
                .split(',')
                .map(|scope| scope.trim().to_string())
                .filter(|scope| !scope.is_empty())
                .collect::<Vec<_>>();
            let cache_secs = env::var("BAY_AUTH_JWKS_CACHE_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(300);

            AuthManager::oidc(OidcConfig {
                jwks_url,
                audience,
                issuer,
                required_scopes,
                cache_ttl: Duration::from_secs(cache_secs),
            })
            .context("failed to initialize OIDC authentication")
        }
        other => anyhow::bail!("unsupported BAY_AUTH_MODE '{other}'"),
    }
}

async fn handle_buoy_ws(
    socket: WebSocket,
    state: Arc<AppState>,
    ip_address: String,
    auth: AuthContext,
) -> Result<()> {
    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(Mutex::new(sender));

    let register_line = loop {
        match receiver.next().await {
            Some(Ok(WsMessage::Text(text))) => break text,
            Some(Ok(WsMessage::Binary(_))) => continue,
            Some(Ok(WsMessage::Ping(payload))) => {
                let _ = sender.lock().await.send(WsMessage::Pong(payload)).await;
            }
            Some(Ok(WsMessage::Pong(_))) => {}
            Some(Ok(WsMessage::Close(_))) | None => {
                anyhow::bail!("connection closed before register")
            }
            Some(Err(err)) => return Err(err.into()),
        }
    };

    let register_msg: ClientToServer = serde_json::from_str(&register_line)?;
    let (local_port, requested_subdomain) = match register_msg {
        ClientToServer::Register {
            local_port,
            requested_subdomain,
            ..
        } => (local_port, requested_subdomain),
        _ => anyhow::bail!("expected register message"),
    };

    let slug = state.allocate_slug(requested_subdomain).await;
    let hostname = format!("{}{}{}", slug, ".", state.domain);

    let (tx, mut rx) = mpsc::channel::<ServerToClient>(32);
    let pending = Arc::new(Mutex::new(HashMap::<
        String,
        oneshot::Sender<ForwardedResponse>,
    >::new()));
    let handle = Arc::new(TunnelHandle {
        hostname: hostname.clone(),
        sender: tx.clone(),
        pending: pending.clone(),
        ip_address: ip_address.clone(),
        owner: auth.clone(),
    });

    state.insert_tunnel(slug.clone(), handle.clone()).await;
    let display_name = auth.email.as_deref().unwrap_or(auth.subject.as_str());
    println!(
        "Buoy registered: user {display_name} (sub {}) from {ip_address} -> {hostname} (local {local_port})",
        auth.subject
    );

    let _ = tx
        .send(ServerToClient::Registered {
            hostname: hostname.clone(),
        })
        .await;

    let writer_sender = sender.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(line) => {
                    if writer_sender
                        .lock()
                        .await
                        .send(WsMessage::Text(line.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("failed to serialize message: {err:?}");
                    break;
                }
            }
        }
    });

    let pending_clone = pending.clone();
    let state_clone = state.clone();
    let slug_clone = slug.clone();
    let reader_task = tokio::spawn(async move {
        while let Some(frame) = receiver.next().await {
            match frame {
                Ok(WsMessage::Text(text)) => match serde_json::from_str::<ClientToServer>(&text) {
                    Ok(ClientToServer::ForwardResponse {
                        request_id,
                        status,
                        headers,
                        body,
                    }) => {
                        let decoded = match general_purpose::STANDARD.decode(body) {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                eprintln!("invalid base64 body: {err:?}");
                                continue;
                            }
                        };
                        if let Some(tx) = pending_clone.lock().await.remove(&request_id) {
                            let _ = tx.send(ForwardedResponse {
                                status,
                                headers,
                                body: decoded,
                            });
                        }
                    }
                    Ok(ClientToServer::Register { .. }) => {
                        eprintln!("buoy attempted to re-register; ignoring");
                    }
                    Err(err) => {
                        eprintln!("invalid message from buoy: {err:?}");
                    }
                },
                Ok(WsMessage::Ping(payload)) => {
                    let _ = sender.lock().await.send(WsMessage::Pong(payload)).await;
                }
                Ok(WsMessage::Pong(_)) => {}
                Ok(WsMessage::Binary(_)) => {}
                Ok(WsMessage::Close(_)) => break,
                Err(err) => {
                    eprintln!("reader error: {err:?}");
                    break;
                }
            }
        }
        state_clone.remove_tunnel(&slug_clone).await;
    });

    tokio::select! {
        _ = writer_task => {}
        _ = reader_task => {}
    }

    let disconnect_name = auth.email.as_deref().unwrap_or(auth.subject.as_str());
    println!(
        "Buoy disconnected: user {disconnect_name} (sub {}) from {ip_address} -> {hostname}",
        auth.subject
    );

    Ok(())
}

fn convert_response(resp: ForwardedResponse) -> Result<Response<Body>, StatusCode> {
    let mut builder = Response::builder().status(resp.status);
    for header in resp.headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::header::HeaderName::from_bytes(header.name.as_bytes()),
            axum::http::header::HeaderValue::from_str(&header.value),
        ) {
            builder = builder.header(name, value);
        }
    }

    builder
        .body(Body::from(resp.body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn header_map_to_proto(map: &axum::http::HeaderMap) -> Vec<Header> {
    map.iter()
        .filter_map(|(name, value)| {
            Some(Header {
                name: name.as_str().to_string(),
                value: value.to_str().ok()?.to_string(),
            })
        })
        .collect()
}

fn extract_slug(host: &str) -> Option<&str> {
    let host = host.split(':').next()?;
    host.split('.').next().filter(|s| !s.is_empty())
}

fn random_slug() -> String {
    let mut rng = rand::rng();
    Alphanumeric.sample_string(&mut rng, 6).to_lowercase()
}

struct AppState {
    domain: String,
    tunnels: RwLock<HashMap<String, Arc<TunnelHandle>>>,
    auth: AuthManager,
}

impl AppState {
    fn new(domain: String, auth: AuthManager) -> Self {
        Self {
            domain,
            tunnels: RwLock::new(HashMap::new()),
            auth,
        }
    }

    #[allow(clippy::collapsible_if)]
    async fn allocate_slug(&self, requested: Option<String>) -> String {
        if let Some(candidate) = requested
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
        {
            if self.is_available(&candidate).await {
                return candidate;
            }
        }

        loop {
            let candidate = random_slug();
            if self.is_available(&candidate).await {
                return candidate;
            }
        }
    }

    async fn is_available(&self, slug: &str) -> bool {
        !self.tunnels.read().await.contains_key(slug)
    }

    async fn insert_tunnel(&self, slug: String, handle: Arc<TunnelHandle>) {
        self.tunnels.write().await.insert(slug, handle);
    }

    async fn remove_tunnel(&self, slug: &str) {
        self.tunnels.write().await.remove(slug);
    }

    async fn get_tunnel(&self, slug: &str) -> Option<Arc<TunnelHandle>> {
        self.tunnels.read().await.get(slug).cloned()
    }

    async fn authenticate(&self, header: Option<&str>) -> Result<AuthContext, AuthError> {
        self.auth.authenticate(header).await
    }
}

struct TunnelHandle {
    #[allow(dead_code)]
    hostname: String,
    sender: mpsc::Sender<ServerToClient>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ForwardedResponse>>>>,
    ip_address: String,
    #[allow(dead_code)]
    owner: AuthContext,
}

struct ForwardedResponse {
    status: u16,
    headers: Vec<Header>,
    body: Vec<u8>,
}
