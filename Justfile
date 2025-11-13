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




