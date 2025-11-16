use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use proto::{
    ClientToServer, DeviceFlowPollResponse, DeviceFlowStartResponse, Header, ServerToClient,
};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client as HttpClient, Method, StatusCode, Url,
};
use tokio::time::sleep;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{
            header::AUTHORIZATION as WS_AUTHORIZATION, HeaderValue as WsHeaderValue,
            StatusCode as WsStatusCode,
        },
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

    let (ws_stream, _) = match connect_async(request).await {
        Ok(conn) => conn,
        Err(err) => {
            if let tokio_tungstenite::tungstenite::Error::Http(response) = &err {
                if matches!(
                    response.status(),
                    WsStatusCode::UNAUTHORIZED | WsStatusCode::FORBIDDEN
                ) && auth_token.is_none()
                {
                    anyhow::bail!("authentication is required but no token is available. Configure bay-managed device login or supply --auth-token/--auth-token-file.");
                }
            }
            return Err(err)
                .with_context(|| format!("failed to connect to bay at {}", args.control_url));
        }
    };
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

    authenticate_via_bay(&args.control_url).await
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

fn control_to_http_base(control_url: &str) -> Result<Url> {
    let mut url =
        Url::parse(control_url).with_context(|| format!("invalid control URL {control_url}"))?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        other => other,
    }
    .to_string();
    url.set_scheme(&scheme)
        .map_err(|_| anyhow!("unsupported control URL scheme {}", url.scheme()))?;
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

async fn authenticate_via_bay(control_url: &str) -> Result<Option<String>> {
    let base = control_to_http_base(control_url)?;
    let client = HttpClient::new();

    let start_url = base
        .join("auth/device")
        .context("failed to build device login endpoint")?;
    let start_response = client.post(start_url.clone()).send().await?;
    match start_response.status() {
        StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED => return Ok(None),
        status if !status.is_success() => {
            let body = start_response.text().await.unwrap_or_default();
            anyhow::bail!(
                "device login unavailable (status {status}): {}",
                body.trim()
            );
        }
        _ => {}
    }

    let start: DeviceFlowStartResponse = start_response
        .json()
        .await
        .context("invalid device login response from bay")?;
    println!("Starting device login via bay – follow the prompts to authenticate...");
    if let Some(uri) = &start.verification_uri_complete {
        println!("Visit {uri} to approve access");
    } else {
        println!(
            "Visit {} and enter the code {}",
            start.verification_uri, start.user_code
        );
    }
    if let Some(message) = &start.message {
        println!("{message}");
    }

    let mut interval = start.interval.max(1);
    let expires_at = Instant::now() + Duration::from_secs(start.expires_in);
    let poll_url = base
        .join(&format!("auth/device/{}/poll", start.flow_id))
        .context("failed to build device poll endpoint")?;

    loop {
        if Instant::now() >= expires_at {
            anyhow::bail!("device authorization expired before approval");
        }

        sleep(Duration::from_secs(interval)).await;

        let response = client.post(poll_url.clone()).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            anyhow::bail!("device authorization session was not found on bay");
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "device authorization failed with status {status}: {}",
                body.trim()
            );
        }

        let poll: DeviceFlowPollResponse = response
            .json()
            .await
            .context("invalid device poll response from bay")?;
        match poll {
            DeviceFlowPollResponse::Pending {
                interval: new_interval,
            } => {
                interval = new_interval.max(1);
            }
            DeviceFlowPollResponse::Approved {
                access_token,
                subject,
                email,
            } => {
                let display_name = email.as_deref().unwrap_or(&subject);
                println!("Authenticated as {display_name}. Continuing with tunnel registration...");
                return Ok(Some(access_token));
            }
            DeviceFlowPollResponse::Denied {
                error,
                error_description,
            } => {
                let description = error_description.unwrap_or_default();
                anyhow::bail!(
                    "the sign-in request was denied: {}",
                    if description.is_empty() {
                        error
                    } else {
                        format!("{error}: {description}")
                    }
                );
            }
            DeviceFlowPollResponse::Expired => {
                anyhow::bail!("device authorization expired before approval");
            }
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

    #[test]
    fn control_to_http_base_converts_ws_to_http() {
        let url = control_to_http_base("wss://example.com:7070/control").unwrap();
        assert_eq!(url.as_str(), "https://example.com:7070/");
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
