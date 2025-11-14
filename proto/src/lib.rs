use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToServer {
    Register {
        client_name: Option<String>,
        local_port: u16,
        requested_subdomain: Option<String>,
    },
    ForwardResponse {
        request_id: String,
        status: u16,
        headers: Vec<Header>,
        body: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerToClient {
    Registered {
        hostname: String,
        url: String,
    },
    ForwardRequest {
        request_id: String,
        method: String,
        path_and_query: String,
        headers: Vec<Header>,
        body: String,
    },
}
