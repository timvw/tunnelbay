# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/timvw/tunnelbay/compare/proto-v0.7.0...proto-v0.8.0) - 2025-11-13

### Added

- OAuth 2.0 device authorization flow for buoy, including CLI prompts and token injection into the websocket handshake
- Control-plane enforcement that requires buoy registrations to present OAuth tokens (docs now include Authentik setup)
