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
- JWT guard with token generation, validation, and refresh
- Session guard with TTL and cleanup
- Policy-based authorization framework
- Gate system (callback, permission, role gates)
- Authorizer with Can/Cannot methods
- HTTP middleware for authentication and authorization
- Memory user provider for testing
- Account locking and email verification support
- Comprehensive test suite with 83.7% coverage
- CI/CD pipeline with GitHub Actions
- Repository setup with MIT license
- Code of Conduct and Contributing guidelines
- README with quick start examples
- Quick Start Guide documentation
- 4 working examples (basic-auth, policy-auth, session-auth, http-middleware)

### Infrastructure
- Go module initialized (`github.com/toutaio/toutago-breitheamh-auth`)
- Standard project structure (pkg, adapters, examples, docs)
- golangci-lint configuration for code quality
- GitHub Actions CI with testing, coverage, security scanning, and benchmarks

## [0.1.0] - 2026-01-02

### Added
- Initial release with core features
- JWT and session-based authentication
- Role-based access control (RBAC)
- Policy and gate authorization
- HTTP middleware
- Comprehensive documentation

[Unreleased]: https://github.com/toutaio/toutago-breitheamh-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/toutaio/toutago-breitheamh-auth/releases/tag/v0.1.0
