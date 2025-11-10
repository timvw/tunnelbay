# TunnelBay

Rust workspace with two binaries:

- `bay`: the relay server. It listens for buoy control connections on `0.0.0.0:7000` and serves public HTTP traffic on `0.0.0.0:8080`.
- `buoy`: the client CLI that runs next to your local service, connects out to a bay instance, and proxies requests to a chosen local TCP port.

## Usage

1. Start the bay server (in one terminal):
   ```bash
   cargo run -p bay
   ```

2. Run your local HTTP service on some port (e.g., 3000).

   ```bash
   uv run python -m http.server 3000
   ```

3. Start a buoy that points at that service:
   ```bash
   cargo run -p buoy -- --port 3000 --bay-addr 127.0.0.1:7000
   ```
   The buoy prints the public hostname (e.g., `abc123.bay.localhost`). Any HTTP request that hits the bay with `Host: abc123.bay.localhost` will be forwarded to `http://127.0.0.1:3000`.

   Environment variables can replace the flags if you prefer:
   ```
   export TUNNELBAY_BAY_ADDR=10.0.0.2:7000
   export TUNNELBAY_LOCAL_PORT=4000
   export TUNNELBAY_SUBDOMAIN=my-app
   cargo run -p buoy
   ```
   CLI arguments always take precedence over the env vars.

4. Hit the tunnel from another terminal using curl:
   ```bash
   curl -H "Host: abc123.bay.localhost" http://127.0.0.1:8080
   ```
   Replace `abc123` with the slug the buoy printed. You should see the content served by your local HTTP server.

### Building container images

Use the provided Justfile targets (requires Docker Buildx):

```bash
just build-bay   # builds linux/amd64 bay image
just build-buoy  # builds linux/amd64 buoy image
```

The workflow `.github/workflows/release-images.yaml` runs the same builds on tags and publishes to GHCR.

## How it works

1. Buoy opens a persistent TCP connection to bay and sends a JSON registration message with the target local port.
2. Bay assigns a hostname (or honors a requested subdomain if available) and keeps track of the buoy connection.
3. When an HTTP request arrives at bay, it looks up the hostname, serializes the request, and forwards it over the buoy connection.
4. Buoy replays the request against the local service and ships the response back to bay, which then returns it to the original HTTP client.

TLS termination, auth, and multi-tenant policies are intentionally out of scope for this first cut; you can place bay behind Traefik or another ingress to add HTTPS.
