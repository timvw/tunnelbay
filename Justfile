# Default
default:
	@just --list

# Build bay image
build-bay:
	@docker build \
		-f docker/bay/Dockerfile \
		-t tunnelbay-bay:dev \
		.

# Build buoy image
build-buoy:
	@docker build \
		-f docker/buoy/Dockerfile \
		-t tunnelbay-buoy:dev \
		.
