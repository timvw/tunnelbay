terraform {
  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2024.12"
    }
  }
}

variable "authentik_url" {
  description = "Base URL of your Authentik instance"
  type        = string
}

variable "authentik_token" {
  description = "API token with admin permissions"
  type        = string
  sensitive   = true
}

provider "authentik" {
  url   = var.authentik_url
  token = var.authentik_token
}

# Common data lookups

data "authentik_flow" "default_authorization" {
  slug = "default-provider-authorization-implicit-consent"
}

data "authentik_flow" "default_invalidation" {
  slug = "default-invalidation-flow"
}

data "authentik_property_mapping_provider_scope" "scope-email" {
  name = "authentik default OAuth Mapping: OpenID 'email'"
}

data "authentik_property_mapping_provider_scope" "scope-profile" {
  name = "authentik default OAuth Mapping: OpenID 'profile'"
}

data "authentik_property_mapping_provider_scope" "scope-openid" {
  name = "authentik default OAuth Mapping: OpenID 'openid'"
}

data "authentik_property_mapping_provider_scope" "scope-offline" {
  name = "authentik default OAuth Mapping: OpenID 'offline_access'"
}

data "authentik_certificate_key_pair" "default" {
  name = "authentik Self-signed Certificate (2025-11)"
}

# Scope mapping that emits a boolean claim Authentik calls "register"
resource "authentik_property_mapping_provider_scope" "tunnelbay_register" {
  name       = "TunnelBay register scope"
  scope_name = "register:buoy"
  expression = <<'EOT'
return {
  "register": True,
}
EOT
}

resource "authentik_group" "tunnelbay_publishers" {
  name = "TunnelBay Publishers"
}

resource "authentik_provider_oauth2" "tunnelbay" {
  name               = "TunnelBay"
  client_id          = "tunnelbay"
  client_type        = "public"
  authorization_flow = data.authentik_flow.default_authorization.id
  invalidation_flow  = data.authentik_flow.default_invalidation.id
  signing_key        = data.authentik_certificate_key_pair.default.id
  sub_mode           = "user_username"

  property_mappings = [
    data.authentik_property_mapping_provider_scope.scope-email.id,
    data.authentik_property_mapping_provider_scope.scope-profile.id,
    data.authentik_property_mapping_provider_scope.scope-openid.id,
    data.authentik_property_mapping_provider_scope.scope-offline.id,
    authentik_property_mapping_provider_scope.tunnelbay_register.id,
  ]

  allowed_redirect_uris = [{
    matching_mode = "strict"
    url           = "urn:ietf:wg:oauth:2.0:oob"
  }]
}

resource "authentik_application" "tunnelbay" {
  name              = "TunnelBay"
  slug              = "tunnelbay"
  protocol_provider = authentik_provider_oauth2.tunnelbay.id
  meta_icon         = "https://raw.githubusercontent.com/tunnelbay/.github/main/profile/tunnelbay.png"
  meta_launch_url   = "https://bay.apps.example.com"
  meta_description  = "Issue OAuth tokens for TunnelBay buoys"
  open_in_new_tab   = true
}

resource "authentik_policy_binding" "tunnelbay_access" {
  target = authentik_application.tunnelbay.uuid
  group  = authentik_group.tunnelbay_publishers.id
  order  = 0
}

output "tunnelbay_oauth_endpoints" {
  value = {
    issuer       = "${var.authentik_url}application/o/tunnelbay/"
    jwks         = "${var.authentik_url}application/o/tunnelbay/jwks/"
    device_flow  = "${var.authentik_url}application/o/device/"
    token        = "${var.authentik_url}application/o/token/"
    client_id    = authentik_provider_oauth2.tunnelbay.client_id
    required_scope = "register:buoy"
  }
}
