use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use proto::{ClientToServer, Header, ServerToClient};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client as HttpClient, Method,
};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};

#[derive(Parser, Debug)]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (ws_stream, _) = connect_async(&args.control_url)
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

    let hostname = wait_for_hostname(&mut ws_reader, &mut ws_writer).await?;
    println!("Tunnel ready: https://{hostname}");
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
            ServerToClient::Registered { hostname } => {
                println!("Updated hostname: {hostname}");
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

async fn wait_for_hostname(
    reader: &mut (impl futures::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
    writer: &mut (impl futures::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
) -> Result<String> {
    while let Some(frame) = reader.next().await {
        match frame {
            Ok(WsMessage::Text(text)) => match serde_json::from_str::<ServerToClient>(&text)? {
                ServerToClient::Registered { hostname } => return Ok(hostname),
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
