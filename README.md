# Rust API Gateway

A high-performance, cloud-native API Gateway built in Rust for containerized deployment in Kubernetes clusters. The gateway serves as a unified entry point for multiple communication protocols (gRPC, REST, WebSocket) with advanced traffic management, security, and observability features.

## 🚀 Features

- **Multi-Protocol Support**: HTTP/REST, gRPC (including streaming), and WebSocket
- **Dynamic Service Discovery**: Kubernetes, Consul, and NATS integration
- **Advanced Load Balancing**: Round-robin, least connections, weighted, and consistent hashing
- **Authentication & Authorization**: JWT, OAuth2/OpenID Connect, API keys, and RBAC
- **Rate Limiting**: Token bucket and sliding window algorithms with Redis support
- **Circuit Breaker**: Automatic failure detection and recovery
- **Request/Response Transformation**: Header manipulation and payload transformation
- **Caching**: Multi-level caching with TTL support and invalidation
- **Observability**: Prometheus metrics, structured logging, and distributed tracing
- **Admin Dashboard**: Web-based management interface with real-time monitoring
- **Hot Configuration Reload**: Zero-downtime configuration updates
- **Kubernetes Native**: Full integration with Kubernetes ecosystem

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Admin Dashboard](#admin-dashboard)
- [Plugin Development](#plugin-development)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## 🏃 Quick Start

### Prerequisites

- Rust 1.75 or later
- Docker (optional, for containerized deployment)
- Kubernetes cluster (optional, for K8s deployment)

### Running Locally

1. Clone the repository:
```bash
git clone https://github.com/your-org/rust-api-gateway.git
cd rust-api-gateway
```

2. Build the project:
```bash
cargo build --release
```

3. Start the gateway:
```bash
cargo run
```

The gateway will start on `http://localhost:8080` with the admin interface on `http://localhost:8081`.

### Docker Quick Start

```bash
docker run -p 8080:8080 -p 8081:8081 rust-api-gateway:latest
```

### Kubernetes Quick Start

```bash
kubectl apply -f k8s/
```

## 📦 Installation

### From Source

```bash
git clone https://github.com/your-org/rust-api-gateway.git
cd rust-api-gateway
cargo install --path .
```

### Using Docker

```bash
docker pull rust-api-gateway:latest
```

### Kubernetes Helm Chart

```bash
helm repo add rust-api-gateway https://charts.rust-api-gateway.io
helm install my-gateway rust-api-gateway/api-gateway
```

## ⚙️ Configuration

The gateway uses YAML configuration files. See the [Configuration Reference](docs/configuration.md) for detailed options.

### Basic Configuration

```yaml
server:
  bind_address: "0.0.0.0"
  http_port: 8080
  admin_port: 8081

routes:
  - path: "/api/users"
    upstream: "user-service"
    methods: ["GET", "POST"]
  - path: "/api/posts"
    upstream: "post-service"
    methods: ["GET", "POST", "PUT", "DELETE"]

upstreams:
  user-service:
    discovery:
      type: "kubernetes"
      namespace: "default"
    load_balancer:
      algorithm: "round_robin"
```

## 📚 Documentation

- [Configuration Reference](docs/configuration.md) - Complete configuration options
- [API Documentation](docs/api.md) - REST API endpoints and examples
- [Admin API Reference](docs/admin-api.md) - Admin interface documentation
- [Plugin Development Guide](docs/plugin-development.md) - Creating custom plugins
- [Deployment Guide](docs/deployment.md) - Production deployment strategies
- [Troubleshooting Guide](docs/troubleshooting.md) - Common issues and solutions
- [Architecture Overview](docs/architecture.md) - System design and components

## 🔧 Admin Dashboard

The gateway includes a comprehensive web-based admin dashboard for monitoring and management:

- **Service Topology**: Visual representation of services and their health
- **Real-time Metrics**: Request rates, latency, and error rates
- **Configuration Management**: Live configuration editing with validation
- **Log Viewer**: Real-time log streaming with filtering
- **User Management**: Admin user and API key management

Access the dashboard at `http://localhost:8081` (default admin port).

## 🔌 Plugin Development

The gateway supports custom middleware plugins. See the [Plugin Development Guide](docs/plugin-development.md) for creating your own plugins.

### Example Plugin

```rust
use api_gateway::middleware::{Middleware, MiddlewareResult};
use async_trait::async_trait;

pub struct CustomAuthMiddleware {
    api_key: String,
}

#[async_trait]
impl Middleware for CustomAuthMiddleware {
    async fn process_request(&self, request: &mut Request) -> MiddlewareResult {
        // Custom authentication logic
        Ok(())
    }
}
```

## 🚀 Deployment

### Docker Deployment

```bash
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 8081:8081 \
  -v $(pwd)/config:/etc/gateway \
  rust-api-gateway:latest
```

### Kubernetes Deployment

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

See the [Deployment Guide](docs/deployment.md) for production deployment strategies.

## 🔍 Troubleshooting

Common issues and solutions:

- **Gateway won't start**: Check configuration file syntax and required dependencies
- **Services not discovered**: Verify service discovery configuration and network connectivity
- **High latency**: Review load balancing configuration and upstream health
- **Authentication failures**: Check JWT configuration and token validity

See the [Troubleshooting Guide](docs/troubleshooting.md) for detailed solutions.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Running Tests

```bash
cargo test
cargo test --features integration-tests
```

### Benchmarks

```bash
cargo bench
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Tokio](https://tokio.rs/) for async runtime
- HTTP server powered by [Axum](https://github.com/tokio-rs/axum)
- gRPC support via [Tonic](https://github.com/hyperium/tonic)
- Observability with [Tracing](https://tracing.rs/)

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/your-org/rust-api-gateway/issues)
- 💬 [Discussions](https://github.com/your-org/rust-api-gateway/discussions)
- 📧 [Email Support](mailto:support@rust-api-gateway.io)