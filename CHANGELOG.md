# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-01-03

### Fixed
- Fixed broken examples to use correct API patterns
- Removed overly complex examples that demonstrated unimplemented features

### Changed
- Updated examples README to reflect available examples
- Simplified example set to focus on core features

### Removed
- Removed placeholder examples: 2fa-example, datamapper-integration, multi-tenant, rbac-admin
- Removed internal summary and progress tracking files

## [0.1.1] - 2026-01-03

### Added
- Comprehensive package documentation (doc.go) for pkg.go.dev
- Release and pre-release GitHub workflows
- Consistent project structure aligned with Toutā ecosystem

### Changed
- Documentation improvements for better discoverability

## [0.1.0] - 2026-01-02

### Added
- Core authentication interfaces (User, Guard, UserProvider, Authenticatable)
- Password hashing utilities with bcrypt and argon2id support
- Base user model implementation with role and permission management
- Wildcard permission matching system (`posts.*`, `*.create`, `*`)
- Guard manager for multi-guard authentication
- JWT guard with token generation, validation, and refresh
- Session guard with TTL and cleanup
- Policy-based authorization framework
- Gate system (callback, permission, role gates)
- Authorizer with Can/Cannot methods
- HTTP middleware for authentication and authorization
- Memory user provider for testing
- Account locking and email verification support
- Comprehensive test suite with 83.7% coverage
- Security tests for timing attacks, token tampering, brute force protection
- CI/CD pipeline with GitHub Actions
- Repository setup with MIT license
- Code of Conduct and Contributing guidelines
- README with quick start examples
- Quick Start Guide documentation
- Working examples: basic-auth, jwt-api, session-auth, http-middleware, policy-authorization, api-token, cosan-integration

### Infrastructure
- Go module initialized (`github.com/toutaio/toutago-breitheamh-auth`)
- Standard project structure (pkg, adapters, examples, docs)
- golangci-lint configuration for code quality
- GitHub Actions CI with testing, coverage, security scanning, and benchmarks

[Unreleased]: https://github.com/toutaio/toutago-breitheamh-auth/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/toutaio/toutago-breitheamh-auth/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/toutaio/toutago-breitheamh-auth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/toutaio/toutago-breitheamh-auth/releases/tag/v0.1.0
