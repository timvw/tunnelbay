use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use proto::{ClientToServer, Header, ServerToClient};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client as HttpClient, Method,
};
use serde::Deserialize;
use tokio::time::sleep;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{header::AUTHORIZATION as WS_AUTHORIZATION, HeaderValue as WsHeaderValue},
        protocol::Message as WsMessage,
    },
};

#[derive(Parser)]
struct Args {
    /// WebSocket URL for the bay control plane
    #[arg(
        long,
        env = "TUNNELBAY_CONTROL_URL",
        default_value = "ws://127.0.0.1:7070/control"
    )]
    control_url: String,
    /// Local TCP port to forward
    #[arg(long, env = "TUNNELBAY_LOCAL_PORT", default_value_t = 3000)]
    port: u16,
    /// Optional requested subdomain/slug
    #[arg(long, env = "TUNNELBAY_SUBDOMAIN")]
    subdomain: Option<String>,
    /// Bearer token to send as Authorization header to bay
    #[arg(long, env = "TUNNELBAY_AUTH_TOKEN", hide_env_values = true)]
    auth_token: Option<String>,
    /// Path to a file that contains the bearer token
    #[arg(long, env = "TUNNELBAY_AUTH_TOKEN_FILE")]
    auth_token_file: Option<PathBuf>,
    /// OAuth 2.0 device authorization endpoint
    #[arg(long, env = "TUNNELBAY_OAUTH_DEVICE_CODE_URL")]
    oauth_device_code_url: Option<String>,
    /// OAuth 2.0 token endpoint used to poll for device flow tokens
    #[arg(long, env = "TUNNELBAY_OAUTH_TOKEN_URL")]
    oauth_token_url: Option<String>,
    /// OAuth 2.0 client ID registered with the identity provider
    #[arg(long, env = "TUNNELBAY_OAUTH_CLIENT_ID")]
    oauth_client_id: Option<String>,
    /// Optional OAuth 2.0 client secret for confidential clients
    #[arg(long, env = "TUNNELBAY_OAUTH_CLIENT_SECRET", hide_env_values = true)]
    oauth_client_secret: Option<String>,
    /// Space-separated scopes requested during OAuth authentication
    #[arg(
        long,
        env = "TUNNELBAY_OAUTH_SCOPE",
        default_value = "openid profile email offline_access"
    )]
    oauth_scope: String,
    /// Optional audience parameter to include in the device authorization request
    #[arg(long, env = "TUNNELBAY_OAUTH_AUDIENCE")]
    oauth_audience: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let auth_token = resolve_auth_token(&args).await?;
    let mut request = args
        .control_url
        .clone()
        .into_client_request()
        .context("failed to prepare control-plane request")?;

    if let Some(token) = auth_token.as_deref() {
        let value = format!("Bearer {token}");
        let header_value =
            WsHeaderValue::from_str(&value).context("invalid characters in bearer token")?;
        request.headers_mut().insert(WS_AUTHORIZATION, header_value);
    }

    let (ws_stream, _) = connect_async(request)
        .await
        .with_context(|| format!("failed to connect to bay at {}", args.control_url))?;
    let (mut ws_writer, mut ws_reader) = ws_stream.split();

    let register = ClientToServer::Register {
        client_name: None,
        local_port: args.port,
        requested_subdomain: args.subdomain.clone(),
    };
    ws_writer
        .send(text_message(serde_json::to_string(&register)?))
        .await
        .context("failed to send register message")?;

    let (hostname, public_url) = wait_for_registration(&mut ws_reader, &mut ws_writer).await?;
    println!("Tunnel ready: {public_url} (hostname {hostname})");
    println!("Forwarding requests to http://127.0.0.1:{}", args.port);

    let client = HttpClient::new();

    while let Some(frame) = ws_reader.next().await {
        let text = match frame {
            Ok(WsMessage::Text(text)) => text,
            Ok(WsMessage::Ping(payload)) => {
                let _ = ws_writer.send(WsMessage::Pong(payload)).await;
                continue;
            }
            Ok(WsMessage::Pong(_)) => continue,
            Ok(WsMessage::Binary(_)) => continue,
            Ok(WsMessage::Close(_)) => break,
            Ok(WsMessage::Frame(_)) => continue,
            Err(err) => return Err(err.into()),
        };

        let message: ServerToClient = serde_json::from_str(&text)?;

        match message {
            ServerToClient::Registered { hostname, url } => {
                println!("Updated tunnel: {url} (hostname {hostname})");
            }
            ServerToClient::ForwardRequest {
                request_id,
                method,
                path_and_query,
                headers,
                body,
            } => {
                let response = match forward_to_local(
                    &client,
                    args.port,
                    request_id.clone(),
                    method,
                    path_and_query,
                    headers,
                    body,
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(err) => {
                        eprintln!("Failed to forward request: {err:?}");
                        build_error_response(request_id)
                    }
                };

                let line = serde_json::to_string(&response)?;
                if ws_writer.send(text_message(line)).await.is_err() {
                    break;
                }
            }
        }
    }

    println!("Bay connection closed");
    Ok(())
}

async fn wait_for_registration(
    reader: &mut (impl futures::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
    writer: &mut (impl futures::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
) -> Result<(String, String)> {
    while let Some(frame) = reader.next().await {
        match frame {
            Ok(WsMessage::Text(text)) => match serde_json::from_str::<ServerToClient>(&text)? {
                ServerToClient::Registered { hostname, url } => return Ok((hostname, url)),
                other => {
                    eprintln!("Received {other:?} before hostname assignment");
                }
            },
            Ok(WsMessage::Ping(payload)) => {
                let _ = writer.send(WsMessage::Pong(payload)).await;
            }
            Ok(WsMessage::Pong(_)) => {}
            Ok(WsMessage::Binary(_)) => {}
            Ok(WsMessage::Close(_)) => break,
            Ok(WsMessage::Frame(_)) => {}
            Err(err) => return Err(err.into()),
        }
    }

    Err(anyhow!("connection closed before registration"))
}

async fn forward_to_local(
    client: &HttpClient,
    local_port: u16,
    request_id: String,
    method: String,
    path_and_query: String,
    headers: Vec<Header>,
    body: String,
) -> Result<ClientToServer> {
    let uri = format!("http://127.0.0.1:{local_port}{path_and_query}");
    let method = method.parse::<Method>()?;
    let mut request = client.request(method, &uri);

    for header in headers {
        if header.name.eq_ignore_ascii_case("host") {
            continue;
        }

        let name = HeaderName::from_bytes(header.name.as_bytes())?;
        let value = HeaderValue::from_str(&header.value)?;
        request = request.header(name, value);
    }

    request = request.header("host", format!("127.0.0.1:{local_port}"));
    let decoded_body = general_purpose::STANDARD.decode(body)?;
    let response = request.body(decoded_body).send().await?;

    let status = response.status().as_u16();
    let response_headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some(Header {
                name: name.as_str().to_string(),
                value: value.to_str().ok()?.to_string(),
            })
        })
        .collect::<Vec<_>>();

    let response_body = response.bytes().await?;
    let encoded_body = general_purpose::STANDARD.encode(response_body);

    Ok(ClientToServer::ForwardResponse {
        request_id,
        status,
        headers: response_headers,
        body: encoded_body,
    })
}

fn text_message(payload: String) -> WsMessage {
    #[allow(clippy::useless_conversion)]
    {
        WsMessage::Text(payload.into())
    }
}

fn build_error_response(request_id: String) -> ClientToServer {
    let payload = "Internal buoy error";
    ClientToServer::ForwardResponse {
        request_id,
        status: 502,
        headers: vec![Header {
            name: "content-type".into(),
            value: "text/plain".into(),
        }],
        body: general_purpose::STANDARD.encode(payload),
    }
}

async fn resolve_auth_token(args: &Args) -> Result<Option<String>> {
    if let Some(token) = args.auth_token.clone() {
        return Ok(Some(token));
    }

    if let Some(path) = &args.auth_token_file {
        return Ok(Some(load_token_from_file(path)?));
    }

    if let Some(config) = DeviceFlowConfig::from_args(args)? {
        let token = run_device_flow(&config).await?;
        return Ok(Some(token));
    }

    Ok(None)
}

fn load_token_from_file(path: &PathBuf) -> Result<String> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read auth token from {}", path.display()))?;
    let token = contents.trim();
    if token.is_empty() {
        anyhow::bail!("auth token file {} is empty", path.display());
    }
    Ok(token.to_string())
}

#[derive(Clone, Debug)]
struct DeviceFlowConfig {
    device_code_url: String,
    token_url: String,
    client_id: String,
    client_secret: Option<String>,
    scope: String,
    audience: Option<String>,
}

impl DeviceFlowConfig {
    fn from_args(args: &Args) -> Result<Option<Self>> {
        match (
            args.oauth_device_code_url.as_ref(),
            args.oauth_token_url.as_ref(),
            args.oauth_client_id.as_ref(),
        ) {
            (Some(device_url), Some(token_url), Some(client_id)) => Ok(Some(Self {
                device_code_url: device_url.clone(),
                token_url: token_url.clone(),
                client_id: client_id.clone(),
                client_secret: args.oauth_client_secret.clone(),
                scope: args.oauth_scope.clone(),
                audience: args.oauth_audience.clone(),
            })),
            (None, None, None) => Ok(None),
            _ => anyhow::bail!(
                "device authorization requires --oauth-device-code-url, --oauth-token-url, and --oauth-client-id"
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
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
struct DeviceTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    _expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

async fn run_device_flow(config: &DeviceFlowConfig) -> Result<String> {
    println!("Starting OAuth device flow – follow the prompts to authenticate...");
    let client = HttpClient::new();

    let mut device_request = vec![
        ("client_id".to_string(), config.client_id.clone()),
        ("scope".to_string(), config.scope.clone()),
    ];
    if let Some(audience) = &config.audience {
        device_request.push(("audience".into(), audience.clone()));
    }

    let device_auth: DeviceAuthorizationResponse = client
        .post(&config.device_code_url)
        .form(&device_request)
        .send()
        .await
        .context("failed to request OAuth device code")?
        .error_for_status()
        .context("device authorization endpoint returned an error")?
        .json()
        .await
        .context("invalid response from device authorization endpoint")?;

    if let Some(uri) = &device_auth.verification_uri_complete {
        println!("Visit {uri} to approve access");
    } else {
        println!(
            "Visit {} and enter the code {}",
            device_auth.verification_uri, device_auth.user_code
        );
    }
    if let Some(message) = &device_auth.message {
        println!("{message}");
    }

    let expires_at = Instant::now() + Duration::from_secs(device_auth.expires_in);
    let mut interval = device_auth.interval.unwrap_or(5).max(1);

    loop {
        if Instant::now() >= expires_at {
            anyhow::bail!("device authorization expired before approval");
        }

        sleep(Duration::from_secs(interval)).await;

        let mut token_request = vec![
            (
                "grant_type".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code".to_string(), device_auth.device_code.clone()),
            ("client_id".to_string(), config.client_id.clone()),
        ];
        if let Some(secret) = &config.client_secret {
            token_request.push(("client_secret".into(), secret.clone()));
        }

        let response = client
            .post(&config.token_url)
            .form(&token_request)
            .send()
            .await
            .context("failed to poll OAuth token endpoint")?;

        if response.status().is_success() {
            let token: DeviceTokenResponse = response
                .json()
                .await
                .context("invalid OAuth token response")?;
            if !token.token_type.eq_ignore_ascii_case("bearer") {
                anyhow::bail!(
                    "token endpoint returned unsupported type {}",
                    token.token_type
                );
            }
            println!("Authentication approved. Continuing with tunnel registration...");
            return Ok(token.access_token);
        }

        let error: DeviceTokenError = response
            .json()
            .await
            .context("invalid error payload from OAuth token endpoint")?;
        match error.error.as_str() {
            "authorization_pending" => continue,
            "slow_down" => {
                interval += 5;
                continue;
            }
            "access_denied" => anyhow::bail!("the sign-in request was denied"),
            "expired_token" => anyhow::bail!("device authorization code expired"),
            other => anyhow::bail!(
                "token endpoint returned {other}: {}",
                error.error_description.unwrap_or_default()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use hyper014::body::to_bytes;
    use hyper014::service::{make_service_fn, service_fn};
    use hyper014::{Body, Request as HyperRequest, Response as HyperResponse, Server, StatusCode};
    use std::convert::Infallible;
    use std::net::TcpListener;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use tokio::sync::{oneshot, Mutex};

    #[test]
    fn build_error_response_encodes_payload() {
        let message = build_error_response("req-123".into());
        match message {
            ClientToServer::ForwardResponse {
                request_id,
                status,
                headers,
                body,
            } => {
                assert_eq!(request_id, "req-123");
                assert_eq!(status, 502);
                assert!(headers
                    .iter()
                    .any(|h| h.name == "content-type" && h.value == "text/plain"));
                let decoded =
                    String::from_utf8(general_purpose::STANDARD.decode(body).unwrap()).unwrap();
                assert_eq!(decoded, "Internal buoy error");
            }
            _ => panic!("unexpected message variant"),
        }
    }

    #[test]
    fn load_token_from_file_reads_trimmed_contents() {
        let mut file = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        file.write_all(b"secret-token\n").unwrap();
        let token = load_token_from_file(&file.path().to_path_buf()).unwrap();
        assert_eq!(token, "secret-token");
    }

    #[tokio::test]
    async fn forward_to_local_replays_request_to_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (capture_tx, capture_rx) = oneshot::channel::<CapturedRequest>();
        let capture = Arc::new(Mutex::new(Some(capture_tx)));

        let server = Server::from_tcp(listener)
            .unwrap()
            .serve(make_service_fn(move |_| {
                let capture = capture.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                        let capture = capture.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let body_bytes = to_bytes(body).await.unwrap().to_vec();
                            let headers = parts
                                .headers
                                .iter()
                                .map(|(name, value)| {
                                    (
                                        name.as_str().to_string(),
                                        value.to_str().unwrap().to_string(),
                                    )
                                })
                                .collect();
                            if let Some(sender) = capture.lock().await.take() {
                                let _ = sender.send(CapturedRequest {
                                    method: parts.method.to_string(),
                                    uri: parts.uri.to_string(),
                                    headers,
                                    body: body_bytes,
                                });
                            }
                            let response = HyperResponse::builder()
                                .status(StatusCode::CREATED)
                                .header("content-type", "text/plain")
                                .body(Body::from("pong"))
                                .unwrap();
                            Ok::<_, Infallible>(response)
                        }
                    }))
                }
            }))
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            });

        let server_handle = tokio::spawn(server);

        let client = HttpClient::new();
        let headers = vec![
            Header {
                name: "host".into(),
                value: "example.com".into(),
            },
            Header {
                name: "x-test".into(),
                value: "123".into(),
            },
        ];
        let body = general_purpose::STANDARD.encode("ping");

        let response = forward_to_local(
            &client,
            port,
            "req-1".into(),
            "POST".into(),
            "/echo?foo=bar".into(),
            headers,
            body,
        )
        .await
        .expect("forward succeeds");

        let captured = capture_rx.await.expect("captured request");
        assert_eq!(captured.method, "POST");
        assert_eq!(captured.uri, "/echo?foo=bar");
        assert_eq!(captured.body, b"ping");

        let host_header = captured
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .expect("host header present");
        assert_eq!(host_header.1, format!("127.0.0.1:{port}"));
        assert!(captured
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-test") && value == "123"));

        match response {
            ClientToServer::ForwardResponse {
                request_id,
                status,
                headers,
                body,
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(status, StatusCode::CREATED.as_u16());
                assert!(headers
                    .iter()
                    .any(|h| h.name == "content-type" && h.value == "text/plain"));
                let decoded = general_purpose::STANDARD.decode(body).unwrap();
                assert_eq!(decoded, b"pong");
            }
            _ => panic!("expected forward response"),
        }

        let _ = shutdown_tx.send(());
        let _ = server_handle.await.unwrap();
    }

    struct CapturedRequest {
        method: String,
        uri: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }
}
