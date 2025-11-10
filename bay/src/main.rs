use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Host, State},
    http::{Request, Response, StatusCode},
    routing::any,
};
use base64::{Engine as _, engine::general_purpose};
use futures::{SinkExt, StreamExt};
use proto::{ClientToServer, Header, ServerToClient};
use rand::{Rng, distributions::Alphanumeric};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock, mpsc, oneshot},
};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};
use uuid::Uuid;

const DEFAULT_DOMAIN: &str = "bay.localhost";
const CONTROL_ADDR: &str = "0.0.0.0:7000";
const HTTP_ADDR: &str = "0.0.0.0:8080";
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

#[tokio::main]
async fn main() -> Result<()> {
    let state = Arc::new(AppState::new(DEFAULT_DOMAIN.into()));

    let http_state = state.clone();
    let ctrl_state = state.clone();

    let http_task = tokio::spawn(async move {
        if let Err(err) = run_http_server(http_state).await {
            eprintln!("http server error: {err:?}");
        }
    });

    let ctrl_task = tokio::spawn(async move {
        if let Err(err) = run_control_listener(ctrl_state).await {
            eprintln!("control listener error: {err:?}");
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
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

async fn run_http_server(state: Arc<AppState>) -> Result<()> {
    let app = Router::new().fallback(any(proxy_handler)).with_state(state);
    let listener = TcpListener::bind(HTTP_ADDR).await?;
    println!("HTTP endpoint listening on http://{HTTP_ADDR}");
    axum::serve(listener, app).await?;
    Ok(())
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

    convert_response(response)
}

async fn run_control_listener(state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(CONTROL_ADDR).await?;
    println!("Waiting for buoy connections on {CONTROL_ADDR}");

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_buoy(stream, addr, state).await {
                eprintln!("connection from {addr} failed: {err:?}");
            }
        });
    }
}

async fn handle_buoy(stream: TcpStream, addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LinesCodec::new());
    let writer = FramedWrite::new(write_half, LinesCodec::new());

    let register_line = reader
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("{addr} disconnected before register"))??;
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
    });

    state.insert_tunnel(slug.clone(), handle.clone()).await;
    println!("Buoy registered: {addr} -> {hostname} (local {local_port})");

    // Writer task
    let mut writer = writer;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let line = serde_json::to_string(&msg);
            match line {
                Ok(line) => {
                    if writer.send(line).await.is_err() {
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

    // Send registration ack
    tx.send(ServerToClient::Registered {
        hostname: hostname.clone(),
    })
    .await
    .ok();

    let pending_clone = pending.clone();
    let state_clone = state.clone();
    let slug_clone = slug.clone();
    let reader_task = tokio::spawn(async move {
        while let Some(line) = reader.next().await {
            let line = match line {
                Ok(line) => line,
                Err(err) => {
                    eprintln!("reader error: {err:?}");
                    break;
                }
            };

            match serde_json::from_str::<ClientToServer>(&line) {
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
            }
        }
        state_clone.remove_tunnel(&slug_clone).await;
    });

    tokio::select! {
        _ = writer_task => {}
        _ = reader_task => {}
    }

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
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

struct AppState {
    domain: String,
    tunnels: RwLock<HashMap<String, Arc<TunnelHandle>>>,
}

impl AppState {
    fn new(domain: String) -> Self {
        Self {
            domain,
            tunnels: RwLock::new(HashMap::new()),
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
}

struct TunnelHandle {
    #[allow(dead_code)]
    hostname: String,
    sender: mpsc::Sender<ServerToClient>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ForwardedResponse>>>>,
}

struct ForwardedResponse {
    status: u16,
    headers: Vec<Header>,
    body: Vec<u8>,
}
