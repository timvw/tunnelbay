# Authentik demo configuration

This directory mirrors the pattern we use for the Kubernetes example: a self-contained set of IaC files that can be copied, tweaked, and applied elsewhere. The Terraform snippet provisions the minimum Authentik resources TunnelBay needs.

## Contents

- `tunnelbay-demo.tf` – Terraform file that creates:
  - `register:buoy` scope mapping that emits a `register` claim
  - public OAuth provider (`client_id = tunnelbay`)
  - application tile bound to the provider
  - `TunnelBay Publishers` group and policy binding restricting access

## Usage

1. Export the Authentik admin credentials (or put them in a `.tfvars`).
   ```bash
   export AUTHENTIK_URL="https://authentik.apps.example.com/"
   export AUTHENTIK_TOKEN="<api-token>"
   ```
2. Initialise and plan/apply inside this directory:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```
3. After apply, configure bay/buoy with the endpoints emitted by the provider:
   ```bash
   BAY_AUTH_MODE=oidc \
   BAY_AUTH_JWKS_URL=https://authentik.apps.example.com/application/o/tunnelbay/jwks/ \
   BAY_AUTH_ISSUER=https://authentik.apps.example.com/application/o/tunnelbay/ \
   BAY_AUTH_AUDIENCE=tunnelbay \
   BAY_AUTH_REQUIRED_SCOPES=register:buoy \
   bay
   ```

This keeps the demo infrastructure alongside the code and makes it easy to evolve together (same approach we took for the k8s manifests).
