use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use proto::{ClientToServer, Header, ServerToClient};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client as HttpClient, Method,
};
use tokio::net::{tcp::OwnedReadHalf, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

#[derive(Parser, Debug)]
struct Args {
    /// Address of the bay control plane (host:port)
    #[arg(long, env = "TUNNELBAY_BAY_ADDR", default_value = "127.0.0.1:7000")]
    bay_addr: String,
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

    let stream = TcpStream::connect(&args.bay_addr)
        .await
        .with_context(|| format!("failed to connect to bay at {}", args.bay_addr))?;

    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, LinesCodec::new());
    let mut writer = FramedWrite::new(write_half, LinesCodec::new());

    let register = ClientToServer::Register {
        client_name: None,
        local_port: args.port,
        requested_subdomain: args.subdomain.clone(),
    };
    writer
        .send(serde_json::to_string(&register)?)
        .await
        .context("failed to send register message")?;

    let hostname = wait_for_hostname(&mut reader).await?;
    println!("Tunnel ready: https://{hostname}");
    println!("Forwarding requests to http://127.0.0.1:{}", args.port);

    let client = HttpClient::new();

    while let Some(line) = reader.next().await {
        let line = match line {
            Ok(line) => line,
            Err(err) => return Err(err.into()),
        };
        let message: ServerToClient = serde_json::from_str(&line)?;

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
                if writer.send(line).await.is_err() {
                    break;
                }
            }
        }
    }

    println!("Bay connection closed");
    Ok(())
}

async fn wait_for_hostname(reader: &mut FramedRead<OwnedReadHalf, LinesCodec>) -> Result<String> {
    while let Some(line) = reader.next().await {
        let line = match line {
            Ok(line) => line,
            Err(err) => return Err(err.into()),
        };
        match serde_json::from_str::<ServerToClient>(&line)? {
            ServerToClient::Registered { hostname } => return Ok(hostname),
            other => {
                // Unexpected request before registration, ignore and continue
                eprintln!("Received {other:?} before hostname assignment");
            }
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
