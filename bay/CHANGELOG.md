# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1](https://github.com/timvw/tunnelbay/compare/bay-v0.8.0...bay-v0.8.1) - 2025-11-14

### Added

- require authenticated buoy registration
- switch control plane to websockets
- initial tunnelbay prototype

### Fixed

- *(deps)* update rust crate thiserror to v2
- include bay/buoy in releases
- adapt bay to axum/rand updates
- *(deps)* update rust crate rand to 0.9
- *(deps)* update rust crate axum to 0.8
- keep bay process alive when ctrl-c handler fails

### Other

- add bay and buoy unit coverage
- release version 0.8.0
- restore bay/buoy publish defaults
- mark bay/buoy for private publishing
- default to sslip domain
- bump crate versions to 0.7.0
- keep release-plz PR-only
- improve bay logs and docker build
- add container workflow and env overrides

## [0.8.0](https://github.com/timvw/tunnelbay/releases/tag/bay-v0.8.0) - 2025-11-14

### Added

- require authenticated buoy registration
- switch control plane to websockets
- initial tunnelbay prototype

### Fixed

- *(deps)* update rust crate thiserror to v2
- include bay/buoy in releases
- adapt bay to axum/rand updates
- *(deps)* update rust crate rand to 0.9
- *(deps)* update rust crate axum to 0.8
- keep bay process alive when ctrl-c handler fails

### Other

- restore bay/buoy publish defaults
- mark bay/buoy for private publishing
- default to sslip domain
- bump crate versions to 0.7.0
- keep release-plz PR-only
- improve bay logs and docker build
- add container workflow and env overrides
