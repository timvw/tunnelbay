# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1](https://github.com/timvw/tunnelbay/compare/buoy-v0.8.0...buoy-v0.8.1) - 2025-11-14

### Added

- require authenticated buoy registration
- add local run tasks and enable ws connect
- switch control plane to websockets
- initial tunnelbay prototype

### Fixed

- include bay/buoy in releases
- adapt buoy messaging to Utf8Bytes
- *(deps)* update rust crate tokio-tungstenite to 0.28

### Other

- clean up buoy test fixture
- add bay and buoy unit coverage
- release version 0.8.0
- restore bay/buoy publish defaults
- mark bay/buoy for private publishing
- bump crate versions to 0.7.0
- keep release-plz PR-only
- fmt after tungstenite helper
- add container workflow and env overrides

## [0.8.0](https://github.com/timvw/tunnelbay/releases/tag/buoy-v0.8.0) - 2025-11-14

### Added

- require authenticated buoy registration
- add local run tasks and enable ws connect
- switch control plane to websockets
- initial tunnelbay prototype

### Fixed

- include bay/buoy in releases
- adapt buoy messaging to Utf8Bytes
- *(deps)* update rust crate tokio-tungstenite to 0.28

### Other

- restore bay/buoy publish defaults
- mark bay/buoy for private publishing
- bump crate versions to 0.7.0
- keep release-plz PR-only
- fmt after tungstenite helper
- add container workflow and env overrides
