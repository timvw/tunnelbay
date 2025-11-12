# Default
default:
	@just --list

# Build bay image
build-bay:
	@docker buildx build \
		--platform linux/amd64 \
		--load \
		-f docker/bay/Dockerfile \
		-t tunnelbay-bay:dev \
		.

# Build buoy image
build-buoy:
	@docker buildx build \
		--platform linux/amd64 \
		--load \
		-f docker/buoy/Dockerfile \
		-t tunnelbay-buoy:dev \
		.

# Run bay locally via cargo
run-bay domain="bay.apps.timvw.be" http_addr="0.0.0.0:8080" control_addr="0.0.0.0:7070":
	@BAY_DOMAIN={{domain}} BAY_HTTP_ADDR={{http_addr}} BAY_CONTROL_ADDR={{control_addr}} cargo run -p bay

# Run bay container with exposed control and HTTP ports
run-bay-container domain="bay.apps.timvw.be" http_port="8080" control_port="7070":
	@docker run --rm \
		--platform linux/amd64 \
		-e BAY_DOMAIN={{domain}} \
		-e BAY_HTTP_ADDR=0.0.0.0:{{http_port}} \
		-e BAY_CONTROL_ADDR=0.0.0.0:{{control_port}} \
		-p {{http_port}}:{{http_port}} \
		-p {{control_port}}:{{control_port}} \
		tunnelbay-bay:dev

# Run buoy locally via cargo
run-buoy port="3000" control_url="ws://127.0.0.1:7070/control":
	@cargo run -p buoy -- --port {{port}} --control-url {{control_url}}
