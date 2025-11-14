# Default
default:
	@just --list

# Build bay binary via cargo
build-bay:
	@cargo build --release -p bay

# Build buoy binary via cargo
build-buoy:
	@cargo build --release -p buoy

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

buoy-timvw local_port='3000':
	export TUNNELBAY_CONTROL_URL="wss://bay.apps.timvw.be/control"; \
	export TUNNELBAY_LOCAL_PORT="{{local_port}}"; \
	export TUNNELBAY_OAUTH_DEVICE_CODE_URL="https://authentik.apps.timvw.be/application/o/device/"; \
	export TUNNELBAY_OAUTH_TOKEN_URL="https://authentik.apps.timvw.be/application/o/token/"; \
	export TUNNELBAY_OAUTH_CLIENT_ID="tunnelbay"; \
	export TUNNELBAY_OAUTH_SCOPE="openid profile email offline_access register:buoy"; \
	export TUNNELBAY_OAUTH_AUDIENCE="tunnelbay"; \
	cargo run -p buoy --release
