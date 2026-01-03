# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (2026-01-03)
- Performance optimizations:
  - Permission caching with configurable TTL
  - Role lookup caching
  - Optimized wildcard permission matching (<100ns per operation)
  - Lazy loading for user relations via provider pattern
  - Query batching for permissions through trie-based matching
- Comprehensive performance benchmarks:
  - Password hashing (bcrypt: ~46ms, argon2: varies)
  - Permission matching (exact and wildcard)
  - Cache operations (get: ~35ns parallel)
  - Concurrent authentication workflows
- Production readiness improvements:
  - Migration guide for v1.0.0
  - Comprehensive code review completed
  - Security scanning with gosec integrated
  - CI/CD pipeline verified and working
  - Tests passing on multiple Go versions (1.21, 1.22, 1.23)
- Ecosystem integration adapters:
  - Toutago framework adapter for seamless integration
  - Cosan router middleware (auth, permission, role-based)
  - Scéla event bus integration for auth events (login, logout, permission changes)
  - Framework integration documentation
- RBAC admin panel example demonstrating role-based access control
- Two-factor authentication (2FA) example with TOTP and backup codes
- Multi-tenant application example with isolated authentication per tenant
- Datamapper integration example showing database-backed user provider pattern
- 11 comprehensive examples covering authentication, authorization, and integrations

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
- Additional BaseUser methods: RecordFailedLogin, Unlock, GenerateEmailVerificationToken, VerifyEmailWithToken
- CI/CD pipeline with GitHub Actions
- Repository setup with MIT license
- Code of Conduct and Contributing guidelines
- README with quick start examples
- Quick Start Guide documentation
- 8 working examples:
  - basic-auth: Simple authentication flow
  - jwt-api: JWT-based API authentication
  - session-auth: Session-based authentication
  - http-middleware: HTTP middleware integration
  - policy-authorization: Policy-based authorization
  - api-token: API token authentication
  - rbac-admin: RBAC admin panel with role-based access control
  - 2fa-example: Two-factor authentication implementation
  - multi-tenant: Multi-tenant application with isolated authentication
  - datamapper-integration: Database integration example with datamapper pattern
  - cosan-integration: Cosan router integration

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
