use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceFlowStartResponse {
    pub flow_id: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
    #[serde(default)]
    pub message: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DeviceFlowPollResponse {
    Pending {
        interval: u64,
    },
    Approved {
        access_token: String,
        subject: String,
        #[serde(default)]
        email: Option<String>,
    },
    Denied {
        error: String,
        #[serde(default)]
        error_description: Option<String>,
    },
    Expired,
}
