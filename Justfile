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

# Run bay container with exposed control and HTTP ports
run-bay domain="bay.apps.timvw.be" http_port="8080" control_port="7070":
	@docker run --rm \
		--platform linux/amd64 \
		-e BAY_DOMAIN={{domain}} \
		-e BAY_HTTP_ADDR=0.0.0.0:{{http_port}} \
		-e BAY_CONTROL_ADDR=0.0.0.0:{{control_port}} \
		-p {{http_port}}:{{http_port}} \
		-p {{control_port}}:{{control_port}} \
		tunnelbay-bay:dev
