# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core authentication interfaces (User, Guard, UserProvider, Authenticatable)
- Password hashing utilities with bcrypt and argon2id support
- Base user model implementation with role and permission management
- Wildcard permission matching system (`posts.*`, `*.create`, `*`)
- Guard manager for multi-guard authentication
- Account locking and email verification support
- Comprehensive test suite with 72.8% coverage
- CI/CD pipeline with GitHub Actions
- Repository setup with MIT license
- Code of Conduct and Contributing guidelines
- README with quick start examples

### Infrastructure
- Go module initialized (`github.com/toutaio/toutago-breitheamh-auth`)
- Standard project structure (pkg, adapters, examples, docs)
- golangci-lint configuration for code quality
- GitHub Actions CI with testing, coverage, security scanning, and benchmarks

## [0.0.1] - 2026-01-02

### Added
- Initial repository setup
- Core interfaces and types
- Password hashing foundation
- Permission matching system
- Base user implementation

[Unreleased]: https://github.com/toutaio/toutago-breitheamh-auth/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/toutaio/toutago-breitheamh-auth/releases/tag/v0.0.1
