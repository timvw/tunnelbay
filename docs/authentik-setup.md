# Authentik setup for TunnelBay

These steps create the OAuth/OpenID provider backing bay’s SSO enforcement. They assume you manage Authentik via Terraform (see `tunnelbay_oauth.tf` in the infrastructure repo).

## 1. Create the TunnelBay scope mapping

```hcl
resource "authentik_property_mapping_provider_scope" "tunnelbay_register" {
  name       = "TunnelBay register scope"
  scope_name = "register:buoy"
  expression = <<'EOT'
return {
  "register": True,
}
EOT
}
```

This causes Authentik to emit a boolean claim `register: true` any time the `register:buoy` scope is granted. Bay accepts either the literal scope or this claim.

## 2. Create the OAuth provider

```hcl
resource "authentik_provider_oauth2" "tunnelbay" {
  name               = "TunnelBay"
  client_id          = "tunnelbay"
  client_type        = "public"
  authorization_flow = data.authentik_flow.default-provider-authorization-implicit-consent.id
  invalidation_flow  = data.authentik_flow.default_invalidation_flow.id
  signing_key        = data.authentik_certificate_key_pair.default.id
  sub_mode           = "user_username"

  property_mappings = [
    data.authentik_property_mapping_provider_scope.scope-email.id,
    data.authentik_property_mapping_provider_scope.scope-profile.id,
    data.authentik_property_mapping_provider_scope.scope-openid.id,
    data.authentik_property_mapping_provider_scope.scope-offline-access.id,
    authentik_property_mapping_provider_scope.tunnelbay_register.id,
  ]

  allowed_redirect_uris = [{
    matching_mode = "strict"
    url           = "urn:ietf:wg:oauth:2.0:oob"
  }]
}
```

Important notes:

- `client_type = "public"` allows the CLI device flow without storing secrets.
- The custom scope mapping must be in `property_mappings`.

## 3. Wire the provider to an application

```hcl
resource "authentik_application" "tunnelbay" {
  name              = "TunnelBay"
  slug              = "tunnelbay"
  protocol_provider = authentik_provider_oauth2.tunnelbay.id
  meta_icon         = "https://raw.githubusercontent.com/tunnelbay/.github/main/profile/tunnelbay.png"
  meta_launch_url   = "https://bay.apps.timvw.be"
  open_in_new_tab   = true
}
```

This surfaces a tile in the Authentik portal and gives us an object to bind policies to.

## 4. Restrict access via a group

```hcl
resource "authentik_group" "tunnelbay_publishers" {
  name = "TunnelBay Publishers"
}

resource "authentik_policy_binding" "tunnelbay_access" {
  target = authentik_application.tunnelbay.uuid
  group  = authentik_group.tunnelbay_publishers.id
  order  = 0
}
```

Only users in this group see/approve the TunnelBay OAuth client, which in turn is what bay enforces.

## 5. Export the integration values for bay/buoy

After `terraform apply`, the relevant URLs are:

- Issuer: `https://authentik.apps.timvw.be/application/o/tunnelbay/`
- JWKS: `https://authentik.apps.timvw.be/application/o/tunnelbay/jwks/`
- Device endpoint: `https://authentik.apps.timvw.be/application/o/device/`
- Token endpoint: `https://authentik.apps.timvw.be/application/o/token/`

Configure bay with:

```bash
export BAY_AUTH_MODE=oidc
export BAY_AUTH_JWKS_URL=.../jwks/
export BAY_AUTH_ISSUER=.../tunnelbay/
export BAY_AUTH_AUDIENCE=tunnelbay
export BAY_AUTH_REQUIRED_SCOPES=register:buoy
```

Configure buoy with:

```bash
export TUNNELBAY_OAUTH_DEVICE_CODE_URL=.../device/
export TUNNELBAY_OAUTH_TOKEN_URL=.../token/
export TUNNELBAY_OAUTH_CLIENT_ID=tunnelbay
export TUNNELBAY_OAUTH_SCOPE="openid profile email offline_access register:buoy"
export TUNNELBAY_OAUTH_AUDIENCE=tunnelbay
```

With these pieces in place, every buoy registration requires an authenticated user who belongs to `TunnelBay Publishers`.
