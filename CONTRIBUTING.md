# Contributing to Rust API Gateway

Thank you for your interest in contributing to the Rust API Gateway! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Code Style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Community](#community)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to help us maintain a welcoming and inclusive community.

## Getting Started

### Prerequisites

- **Rust**: Version 1.75 or later
- **Git**: For version control
- **Docker**: For containerized testing (optional)
- **Kubernetes**: For integration testing (optional)

### First-time Contributors

If you're new to Rust or open source contribution:

1. **Learn Rust**: Check out [The Rust Book](https://doc.rust-lang.org/book/) and [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
2. **Understand the Project**: Read the [README](README.md) and [Architecture Overview](docs/architecture.md)
3. **Start Small**: Look for issues labeled `good first issue` or `help wanted`
4. **Ask Questions**: Don't hesitate to ask questions in issues or discussions

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/rust-api-gateway.git
cd rust-api-gateway

# Add the upstream repository
git remote add upstream https://github.com/original-org/rust-api-gateway.git
```

### 2. Install Dependencies

```bash
# Install Rust if you haven't already
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install additional tools
cargo install cargo-watch cargo-audit cargo-deny
```

### 3. Build and Test

```bash
# Build the project
cargo build

# Run tests
cargo test

# Run with file watching for development
cargo watch -x run
```

### 4. Development Environment

```bash
# Set up development configuration
cp config/gateway.yaml config/development.yaml

# Start development dependencies (Redis, etc.)
docker-compose -f docker-compose.dev.yml up -d

# Run the gateway in development mode
RUST_LOG=debug cargo run -- --config config/development.yaml
```

## Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

- **Bug Fixes**: Fix issues and improve stability
- **Features**: Add new functionality
- **Documentation**: Improve docs, examples, and comments
- **Performance**: Optimize performance and reduce resource usage
- **Testing**: Add tests and improve test coverage
- **Refactoring**: Improve code quality and maintainability

### Before You Start

1. **Check Existing Issues**: Look for existing issues or discussions about your idea
2. **Create an Issue**: For significant changes, create an issue to discuss the approach
3. **Get Feedback**: Engage with maintainers and community members
4. **Plan Your Work**: Break large changes into smaller, manageable pieces

### Branching Strategy

```bash
# Create a feature branch from main
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name

# Make your changes and commit
git add .
git commit -m "Add feature: your feature description"

# Push to your fork
git push origin feature/your-feature-name
```

## Code Style

### Rust Style Guidelines

We follow the official Rust style guidelines with some project-specific conventions:

#### Formatting

```bash
# Use rustfmt for consistent formatting
cargo fmt

# Check formatting without making changes
cargo fmt -- --check
```

#### Linting

```bash
# Use clippy for linting
cargo clippy

# Fix clippy warnings automatically where possible
cargo clippy --fix
```

#### Naming Conventions

- **Functions and Variables**: `snake_case`
- **Types and Traits**: `PascalCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Modules**: `snake_case`

#### Documentation

- **Public APIs**: Must have documentation comments (`///`)
- **Modules**: Should have module-level documentation (`//!`)
- **Examples**: Include examples in documentation where helpful
- **Rust Concepts**: Explain Rust-specific concepts for newcomers

```rust
/// Processes incoming HTTP requests through the middleware pipeline.
///
/// This function demonstrates Rust's ownership system:
/// - `request` is moved into the function (ownership transfer)
/// - `&mut context` is a mutable reference (borrowed, not owned)
/// - The return type `GatewayResult<Response>` uses Rust's Result type for error handling
///
/// # Arguments
///
/// * `request` - The incoming HTTP request (ownership transferred)
/// * `context` - Mutable reference to the request context
///
/// # Returns
///
/// Returns `Ok(Response)` on success or `Err(GatewayError)` on failure.
///
/// # Examples
///
/// ```rust
/// let request = Request::new("GET", "/api/users");
/// let mut context = RequestContext::new();
/// let response = process_request(request, &mut context).await?;
/// ```
pub async fn process_request(
    request: Request,
    context: &mut RequestContext,
) -> GatewayResult<Response> {
    // Implementation here
}
```

### Error Handling

- Use `Result<T, E>` for fallible operations
- Create specific error types for different error conditions
- Use the `?` operator for error propagation
- Provide helpful error messages with context

```rust
// Good: Specific error with context
fn parse_config(path: &str) -> GatewayResult<Config> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| GatewayError::config(format!("Failed to read config file '{}': {}", path, e)))?;
    
    serde_yaml::from_str(&content)
        .map_err(|e| GatewayError::config(format!("Invalid YAML in '{}': {}", path, e)))
}
```

### Async Programming

- Use `async/await` for I/O operations
- Prefer `tokio::spawn` for independent tasks
- Use `Arc` for shared state between tasks
- Handle cancellation gracefully

```rust
// Good: Proper async error handling
async fn fetch_service_health(url: &str) -> GatewayResult<HealthStatus> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| GatewayError::HttpClient { message: e.to_string() })?;
    
    if response.status().is_success() {
        Ok(HealthStatus::Healthy)
    } else {
        Ok(HealthStatus::Unhealthy)
    }
}
```

## Testing

### Test Categories

1. **Unit Tests**: Test individual functions and modules
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete request flows
4. **Performance Tests**: Benchmark critical paths

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_request_routing() {
        // Arrange
        let router = Router::new();
        router.add_route("/api/users/{id}", "user-service").await;
        let request = Request::new("GET", "/api/users/123");

        // Act
        let route = router.match_route(&request).await.unwrap();

        // Assert
        assert_eq!(route.upstream, "user-service");
        assert_eq!(route.params.get("id"), Some(&"123".to_string()));
    }

    #[test]
    fn test_error_status_mapping() {
        let error = GatewayError::Authentication { reason: "invalid token".to_string() };
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_request_routing

# Run tests with coverage
cargo tarpaulin --out Html
```

### Integration Tests

```bash
# Run integration tests (requires Docker)
cargo test --features integration-tests

# Run with test containers
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

## Documentation

### Types of Documentation

1. **Code Documentation**: Inline comments and doc comments
2. **API Documentation**: Generated from doc comments
3. **User Guides**: How-to guides and tutorials
4. **Architecture Documentation**: Design decisions and patterns

### Writing Documentation

- **Be Clear**: Use simple, clear language
- **Provide Examples**: Include code examples where helpful
- **Explain Rust Concepts**: Help developers from other languages
- **Keep Updated**: Update docs when changing code

### Generating Documentation

```bash
# Generate and open documentation
cargo doc --open

# Generate documentation for all dependencies
cargo doc --document-private-items --open
```

## Pull Request Process

### Before Submitting

1. **Update Your Branch**: Rebase on the latest main branch
2. **Run Tests**: Ensure all tests pass
3. **Check Formatting**: Run `cargo fmt` and `cargo clippy`
4. **Update Documentation**: Update relevant documentation
5. **Write Good Commit Messages**: Follow conventional commit format

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(auth): add JWT token validation
fix(router): handle empty path parameters correctly
docs(api): update authentication examples
test(middleware): add rate limiting tests
```

### Pull Request Template

When creating a pull request, include:

- **Description**: What changes were made and why
- **Testing**: How the changes were tested
- **Documentation**: What documentation was updated
- **Breaking Changes**: Any breaking changes and migration guide
- **Related Issues**: Link to related issues

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and checks
2. **Code Review**: Maintainers and community members review
3. **Feedback**: Address feedback and make requested changes
4. **Approval**: Get approval from maintainers
5. **Merge**: Maintainers merge the pull request

## Issue Reporting

### Bug Reports

When reporting bugs, include:

- **Environment**: OS, Rust version, gateway version
- **Steps to Reproduce**: Clear steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Logs**: Relevant log output or error messages
- **Configuration**: Relevant configuration (sanitized)

### Feature Requests

When requesting features, include:

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: What alternatives have you considered?
- **Additional Context**: Any additional information

### Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements or additions to documentation
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention is needed
- `question`: Further information is requested

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Discord**: Real-time chat (link in README)
- **Email**: security@rust-api-gateway.io for security issues

### Getting Help

- **Documentation**: Check the docs first
- **Search Issues**: Look for existing issues
- **Ask Questions**: Create a discussion or issue
- **Be Patient**: Maintainers are volunteers

### Helping Others

- **Answer Questions**: Help other users in issues and discussions
- **Review Pull Requests**: Provide feedback on contributions
- **Improve Documentation**: Help make docs better
- **Share Knowledge**: Write blog posts or tutorials

## Recognition

Contributors are recognized in several ways:

- **Contributors List**: Listed in README and releases
- **Changelog**: Contributions mentioned in changelog
- **Social Media**: Highlighted on project social media
- **Swag**: Stickers and swag for significant contributions

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (MIT License).

Thank you for contributing to the Rust API Gateway! Your contributions help make this project better for everyone.