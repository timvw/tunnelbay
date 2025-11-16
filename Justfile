set dotenv-load := true

# Default
default:
	@just --list

# Build bay container image
build-bay-container:
	@docker buildx build \
		--platform linux/amd64 \
		--load \
		-f docker/bay/Dockerfile \
		-t tunnelbay-bay:dev \
		.

# Build buoy container image
build-buoy-container:
	@docker buildx build \
		--platform linux/amd64 \
		--load \
		-f docker/buoy/Dockerfile \
		-t tunnelbay-buoy:dev \
		.

bay-local http-addr='0.0.0.0:8080' control-addr='127.0.0.1:7070' domain='127.0.0.1.sslip.io' *params='':
	cargo run -p bay --release -- --http-addr {{http-addr}} --control-addr {{control-addr}} --domain {{domain}} {{params}}

# Run bay locally with OIDC + device flow (defaults to authentik.apps.timvw.be endpoints).
bay-local-oidc http_port='8080' control_port='7070' domain='127.0.0.1.sslip.io':
	: "${BAY_AUTH_CLIENT_SECRET:?set BAY_AUTH_CLIENT_SECRET in your environment or .env}"
	BAY_DOMAIN={{domain}} \
	BAY_HTTP_ADDR=0.0.0.0:{{http_port}} \
	BAY_PUBLIC_SCHEME=http \
	BAY_PUBLIC_PORT={{http_port}} \
	BAY_CONTROL_ADDR=0.0.0.0:{{control_port}} \
	BAY_AUTH_MODE=oidc \
	BAY_AUTH_JWKS_URL=https://authentik.apps.timvw.be/application/o/tunnelbay/jwks/ \
	BAY_AUTH_ISSUER=https://authentik.apps.timvw.be/application/o/tunnelbay/ \
	BAY_AUTH_AUDIENCE=${BAY_AUTH_AUDIENCE:-tunnelbay} \
	BAY_AUTH_REQUIRED_SCOPES=register:buoy \
	BAY_AUTH_DEVICE_CODE_URL=https://authentik.apps.timvw.be/application/o/device/ \
	BAY_AUTH_TOKEN_URL=https://authentik.apps.timvw.be/application/o/token/ \
	BAY_AUTH_CLIENT_ID=${BAY_AUTH_CLIENT_ID:-tunnelbay} \
	BAY_AUTH_CLIENT_SECRET="${BAY_AUTH_CLIENT_SECRET}" \
	BAY_AUTH_SCOPE="openid profile email register:buoy" \
	cargo run -p bay --release

# Run buoy against the local bay, relying on bay-managed device login.
# Optionally override the local port via parameter or env.
buoy-local local_port='3000':
	cargo run -p buoy --release -- --port {{local_port}}

buoy-timvw local_port='3000':
	cargo run -p buoy --release -- --port {{local_port}} --control-url wss://bay.apps.timvw.be/control
