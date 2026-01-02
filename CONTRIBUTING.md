# Contributing to Breitheamh Auth

Thank you for your interest in contributing to Breitheamh Auth! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/toutago-breitheamh-auth.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test ./...`
6. Run linter: `golangci-lint run`
7. Commit your changes: `git commit -m "Add your feature"`
8. Push to your fork: `git push origin feature/your-feature-name`
9. Open a Pull Request

## Code Standards

- Follow Go best practices and idioms
- Write tests for new functionality (target: 80%+ coverage)
- Keep functions small and focused
- Use meaningful variable and function names
- Add godoc comments for exported types and functions
- Run `gofmt` and `goimports` before committing
- Ensure all linter checks pass

## Testing

- Write unit tests for all new code
- Include table-driven tests where appropriate
- Test edge cases and error conditions
- Use the race detector: `go test -race ./...`
- Aim for at least 80% code coverage

## Documentation

- Update README.md if adding new features
- Add godoc comments to all exported symbols
- Include usage examples in documentation
- Update CHANGELOG.md following Keep a Changelog format

## Pull Request Process

1. Ensure all tests pass and coverage meets threshold
2. Update documentation as needed
3. Add your changes to CHANGELOG.md under "Unreleased"
4. Reference any related issues in the PR description
5. Wait for review from maintainers
6. Address review feedback promptly

## Reporting Issues

- Use the GitHub issue tracker
- Check for existing issues before creating new ones
- Provide a clear description and reproduction steps
- Include Go version and operating system information

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
