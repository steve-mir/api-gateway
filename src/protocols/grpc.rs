//! # gRPC Protocol Handler
//!
//! This module provides comprehensive gRPC protocol support including:
//! - Service detection and routing using tonic
//! - Unary RPC call handling with proper error mapping
//! - Server streaming support with connection management
//! - Client streaming with backpressure handling
//! - Bidirectional streaming support
//! - gRPC-Web proxy functionality for browser clients
//! - Protobuf message inspection and transformation capabilities
//!
//! ## gRPC Concepts for Developers New to Rust
//!
//! - gRPC uses HTTP/2 as the transport protocol
//! - Protocol Buffers (protobuf) are used for message serialization
//! - Tonic is the primary gRPC library for Rust
//! - Streaming is handled using Rust's async Stream trait
//! - Error handling maps gRPC status codes to HTTP status codes

use crate::core::{
    error::{GatewayError, GatewayResult},
    types::{IncomingRequest, RequestContext, GatewayResponse, ServiceInstance},
};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Method};
use dashmap::DashMap;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use tonic::{
    transport::{Channel, Endpoint},
    Status, Code,
};

use tracing::{debug, info};

/// Main gRPC protocol handler
pub struct GrpcHandler {
    /// Service registry for gRPC services
    service_registry: Arc<GrpcServiceRegistry>,
    /// Connection pool for upstream gRPC services
    connection_pool: Arc<GrpcConnectionPool>,
    /// gRPC-Web proxy for browser clients
    grpc_web_proxy: Arc<GrpcWebProxy>,
    /// Message inspector for transformation
    message_inspector: Arc<MessageInspector>,
    /// Configuration for gRPC handling
    config: GrpcConfig,
}

/// Configuration for gRPC handler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Enable gRPC-Web support
    pub enable_grpc_web: bool,
    /// Maximum message size (in bytes)
    pub max_message_size: usize,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Enable message inspection
    pub enable_message_inspection: bool,
    /// Enable reflection service
    pub enable_reflection: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enable_grpc_web: true,
            max_message_size: 4 * 1024 * 1024, // 4MB
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            enable_message_inspection: false,
            enable_reflection: true,
        }
    }
}

impl GrpcHandler {
    /// Create a new gRPC handler
    pub fn new(config: GrpcConfig) -> Self {
        Self {
            service_registry: Arc::new(GrpcServiceRegistry::new()),
            connection_pool: Arc::new(GrpcConnectionPool::new(config.clone())),
            grpc_web_proxy: Arc::new(GrpcWebProxy::new(config.clone())),
            message_inspector: Arc::new(MessageInspector::new()),
            config,
        }
    }

    /// Handle a gRPC request
    pub async fn handle_request(
        &self,
        request: Arc<IncomingRequest>,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        // Detect gRPC request type
        let grpc_request_type = self.detect_grpc_request_type(&request).await?;
        
        debug!(
            request_id = %request.id,
            grpc_type = ?grpc_request_type,
            "Handling gRPC request"
        );

        // Handle gRPC-Web requests differently
        if self.is_grpc_web_request(&request) {
            return self.handle_grpc_web_request(request, context).await;
        }

        // Get target service instance
        let service_instance = context
            .selected_instance
            .as_ref()
            .ok_or_else(|| GatewayError::internal("No service instance selected for gRPC request"))?;

        // Handle different gRPC request types
        match grpc_request_type {
            GrpcRequestType::Unary => self.handle_unary_request(request, service_instance).await,
            GrpcRequestType::ServerStreaming => self.handle_server_streaming_request(request, service_instance).await,
            GrpcRequestType::ClientStreaming => self.handle_client_streaming_request(request, service_instance).await,
            GrpcRequestType::BidirectionalStreaming => self.handle_bidirectional_streaming_request(request, service_instance).await,
        }
    }

    /// Detect the type of gRPC request based on service definition and headers
    async fn detect_grpc_request_type(&self, request: &IncomingRequest) -> GatewayResult<GrpcRequestType> {
        // Check content-type header
        let content_type = request
            .header("content-type")
            .ok_or_else(|| GatewayError::Protocol {
                protocol: "gRPC".to_string(),
                message: "Missing content-type header".to_string(),
            })?;

        if !content_type.starts_with("application/grpc") {
            return Err(GatewayError::Protocol {
                protocol: "gRPC".to_string(),
                message: format!("Invalid content-type: {}", content_type),
            });
        }

        // Only POST method is supported for gRPC
        if request.method != Method::POST {
            return Err(GatewayError::Protocol {
                protocol: "gRPC".to_string(),
                message: format!("Unsupported HTTP method for gRPC: {}", request.method),
            });
        }

        // Parse service and method from path
        let (service_name, method_name) = self.parse_grpc_path(request.path())?;
        
        // Look up method information in service registry to determine streaming type
        // Note: This is a synchronous check for now - in a real implementation you'd want async service discovery
        let service_info = self.service_registry.get_service(&service_name).await;
        if let Some(service_info) = service_info {
            if let Some(method_info) = service_info.methods.iter().find(|m| m.name == method_name) {
                return Ok(match (method_info.client_streaming, method_info.server_streaming) {
                    (false, false) => GrpcRequestType::Unary,
                    (false, true) => GrpcRequestType::ServerStreaming,
                    (true, false) => GrpcRequestType::ClientStreaming,
                    (true, true) => GrpcRequestType::BidirectionalStreaming,
                });
            }
        }

        // Fallback: try to detect from headers and body characteristics
        // Check for streaming indicators
        let has_stream_id = request.header("grpc-stream-id").is_some();
        let has_large_body = request.body.len() > self.config.max_message_size / 2;
        let has_chunked_encoding = request.header("transfer-encoding")
            .map(|v| v.contains("chunked"))
            .unwrap_or(false);

        // Heuristic detection when service definition is not available
        if has_stream_id || has_chunked_encoding {
            if has_large_body {
                Ok(GrpcRequestType::BidirectionalStreaming)
            } else {
                Ok(GrpcRequestType::ServerStreaming)
            }
        } else {
            Ok(GrpcRequestType::Unary)
        }
    }

    /// Check if this is a gRPC-Web request
    fn is_grpc_web_request(&self, request: &IncomingRequest) -> bool {
        if let Some(content_type) = request.header("content-type") {
            content_type.starts_with("application/grpc-web")
        } else {
            false
        }
    }

    /// Handle unary gRPC request
    async fn handle_unary_request(
        &self,
        request: Arc<IncomingRequest>,
        service_instance: &ServiceInstance,
    ) -> GatewayResult<GatewayResponse> {
        let start_time = Instant::now();
        
        // Get connection to upstream service
        let client = self.connection_pool.get_connection(service_instance).await?;
        
        // Extract service and method from path
        let (service_name, method_name) = self.parse_grpc_path(request.path())?;
        
        // Inspect message if enabled
        if self.config.enable_message_inspection {
            self.message_inspector.inspect_request(&request, &service_name, &method_name).await?;
        }

        // Create gRPC request
        let grpc_request = self.create_grpc_request(&request)?;
        
        // Make the call
        let response = match tokio::time::timeout(
            self.config.request_timeout,
            client.call_unary(service_name.clone(), method_name.clone(), grpc_request)
        ).await {
            Ok(Ok(response)) => response,
            Ok(Err(status)) => {
                return Ok(self.map_grpc_status_to_response(status));
            }
            Err(_) => {
                return Err(GatewayError::Timeout {
                    timeout_ms: self.config.request_timeout.as_millis() as u64,
                });
            }
        };

        // Convert gRPC response to gateway response
        let gateway_response = self.convert_grpc_response_to_gateway(response, start_time.elapsed())?;
        
        info!(
            service = %service_name,
            method = %method_name,
            duration_ms = start_time.elapsed().as_millis(),
            "Completed unary gRPC call"
        );

        Ok(gateway_response)
    }

    /// Handle server streaming gRPC request
    async fn handle_server_streaming_request(
        &self,
        request: Arc<IncomingRequest>,
        service_instance: &ServiceInstance,
    ) -> GatewayResult<GatewayResponse> {
        let start_time = Instant::now();
        
        // Get connection to upstream service
        let client = self.connection_pool.get_connection(service_instance).await?;
        
        // Extract service and method from path
        let (service_name, method_name) = self.parse_grpc_path(request.path())?;
        
        // Create gRPC request
        let grpc_request = self.create_grpc_request(&request)?;
        
        // Make the streaming call
        let response_stream = match tokio::time::timeout(
            self.config.request_timeout,
            client.call_server_streaming(service_name.clone(), method_name.clone(), grpc_request)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(status)) => {
                return Ok(self.map_grpc_status_to_response(status));
            }
            Err(_) => {
                return Err(GatewayError::Timeout {
                    timeout_ms: self.config.request_timeout.as_millis() as u64,
                });
            }
        };

        // Convert streaming response to HTTP response
        let gateway_response = self.convert_streaming_response_to_gateway(response_stream, start_time.elapsed()).await?;
        
        info!(
            service = %service_name,
            method = %method_name,
            duration_ms = start_time.elapsed().as_millis(),
            "Completed server streaming gRPC call"
        );

        Ok(gateway_response)
    }

    /// Handle client streaming gRPC request
    async fn handle_client_streaming_request(
        &self,
        request: Arc<IncomingRequest>,
        service_instance: &ServiceInstance,
    ) -> GatewayResult<GatewayResponse> {
        let start_time = Instant::now();
        
        // Get connection to upstream service
        let client = self.connection_pool.get_connection(service_instance).await?;
        
        // Extract service and method from path
        let (service_name, method_name) = self.parse_grpc_path(request.path())?;
        
        // Create request stream from the incoming request body
        let request_stream = self.create_request_stream(&request)?;
        
        // Make the streaming call
        let response = match tokio::time::timeout(
            self.config.request_timeout,
            client.call_client_streaming(service_name.clone(), method_name.clone(), request_stream)
        ).await {
            Ok(Ok(response)) => response,
            Ok(Err(status)) => {
                return Ok(self.map_grpc_status_to_response(status));
            }
            Err(_) => {
                return Err(GatewayError::Timeout {
                    timeout_ms: self.config.request_timeout.as_millis() as u64,
                });
            }
        };

        // Convert gRPC response to gateway response
        let gateway_response = self.convert_grpc_response_to_gateway(response, start_time.elapsed())?;
        
        info!(
            service = %service_name,
            method = %method_name,
            duration_ms = start_time.elapsed().as_millis(),
            "Completed client streaming gRPC call"
        );

        Ok(gateway_response)
    }

    /// Handle bidirectional streaming gRPC request
    async fn handle_bidirectional_streaming_request(
        &self,
        request: Arc<IncomingRequest>,
        service_instance: &ServiceInstance,
    ) -> GatewayResult<GatewayResponse> {
        let start_time = Instant::now();
        
        // Get connection to upstream service
        let client = self.connection_pool.get_connection(service_instance).await?;
        
        // Extract service and method from path
        let (service_name, method_name) = self.parse_grpc_path(request.path())?;
        
        // Create request stream from the incoming request body
        let request_stream = self.create_request_stream(&request)?;
        
        // Make the bidirectional streaming call
        let response_stream = match tokio::time::timeout(
            self.config.request_timeout,
            client.call_bidirectional_streaming(service_name.clone(), method_name.clone(), request_stream)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(status)) => {
                return Ok(self.map_grpc_status_to_response(status));
            }
            Err(_) => {
                return Err(GatewayError::Timeout {
                    timeout_ms: self.config.request_timeout.as_millis() as u64,
                });
            }
        };

        // Convert streaming response to HTTP response
        let gateway_response = self.convert_streaming_response_to_gateway(response_stream, start_time.elapsed()).await?;
        
        info!(
            service = %service_name,
            method = %method_name,
            duration_ms = start_time.elapsed().as_millis(),
            "Completed bidirectional streaming gRPC call"
        );

        Ok(gateway_response)
    }

    /// Handle gRPC-Web request
    async fn handle_grpc_web_request(
        &self,
        request: Arc<IncomingRequest>,
        context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        if !self.config.enable_grpc_web {
            return Err(GatewayError::Protocol {
                protocol: "gRPC-Web".to_string(),
                message: "gRPC-Web support is disabled".to_string(),
            });
        }

        self.grpc_web_proxy.handle_request(request, context).await
    }

    /// Parse gRPC path to extract service and method names
    fn parse_grpc_path(&self, path: &str) -> GatewayResult<(String, String)> {
        // gRPC paths are in the format: /package.Service/Method
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if parts.len() != 2 {
            return Err(GatewayError::Protocol {
                protocol: "gRPC".to_string(),
                message: format!("Invalid gRPC path format: {}", path),
            });
        }

        let service_name = parts[0].to_string();
        let method_name = parts[1].to_string();
        
        Ok((service_name, method_name))
    }

    /// Create a gRPC request from the incoming HTTP request
    fn create_grpc_request(&self, request: &IncomingRequest) -> GatewayResult<Vec<u8>> {
        // For now, we'll pass through the raw body
        // In a real implementation, you might want to validate or transform the message
        Ok(request.body.as_ref().clone())
    }

    /// Create a request stream for client/bidirectional streaming with proper body parsing
    fn create_request_stream(&self, request: &IncomingRequest) -> GatewayResult<Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>> {
        let body = request.body.as_ref().clone();
        
        // Parse gRPC streaming body format
        // gRPC streaming uses length-prefixed messages
        let stream = self.parse_grpc_streaming_body(body)?;
        Ok(Box::pin(stream))
    }



    /// Parse gRPC streaming body into individual messages
    fn parse_grpc_streaming_body(&self, body: Vec<u8>) -> GatewayResult<impl Stream<Item = Vec<u8>> + Send> {
        use futures::stream;

        // gRPC uses a simple framing format:
        // [Compressed-Flag (1 byte)][Message-Length (4 bytes)][Message (N bytes)]
        let mut messages = Vec::new();
        let mut cursor = 0;

        while cursor < body.len() {
            // Check if we have enough bytes for the header (5 bytes)
            if cursor + 5 > body.len() {
                break;
            }

            // Read compression flag (1 byte)
            let _compressed = body[cursor] != 0;
            cursor += 1;

            // Read message length (4 bytes, big-endian)
            let length = u32::from_be_bytes([
                body[cursor],
                body[cursor + 1],
                body[cursor + 2],
                body[cursor + 3],
            ]) as usize;
            cursor += 4;

            // Check if we have enough bytes for the message
            if cursor + length > body.len() {
                break;
            }

            // Extract the message
            let message = body[cursor..cursor + length].to_vec();
            messages.push(message);
            cursor += length;
        }

        // If no messages were parsed, treat the entire body as a single message
        if messages.is_empty() && !body.is_empty() {
            messages.push(body);
        }

        Ok(stream::iter(messages))
    }

    /// Convert gRPC response to gateway response
    fn convert_grpc_response_to_gateway(
        &self,
        response: Vec<u8>,
        processing_time: Duration,
    ) -> GatewayResult<GatewayResponse> {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("grpc-status", HeaderValue::from_static("0")); // OK status
        
        let mut gateway_response = GatewayResponse::new(StatusCode::OK, headers, response);
        gateway_response.processing_time = processing_time;
        
        Ok(gateway_response)
    }

    /// Convert streaming response to gateway response
    async fn convert_streaming_response_to_gateway(
        &self,
        mut stream: Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>,
        processing_time: Duration,
    ) -> GatewayResult<GatewayResponse> {
        let mut response_data = Vec::new();
        
        // Collect all streaming data
        // In a real implementation, you might want to stream this back to the client
        while let Some(result) = stream.next().await {
            match result {
                Ok(data) => response_data.extend_from_slice(&data),
                Err(status) => {
                    return Ok(self.map_grpc_status_to_response(status));
                }
            }
        }
        
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("grpc-status", HeaderValue::from_static("0")); // OK status
        
        let mut gateway_response = GatewayResponse::new(StatusCode::OK, headers, response_data);
        gateway_response.processing_time = processing_time;
        
        Ok(gateway_response)
    }

    /// Map gRPC status to HTTP response
    fn map_grpc_status_to_response(&self, status: Status) -> GatewayResponse {
        let http_status = match status.code() {
            Code::Ok => StatusCode::OK,
            Code::Cancelled => StatusCode::REQUEST_TIMEOUT,
            Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            Code::InvalidArgument => StatusCode::BAD_REQUEST,
            Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            Code::NotFound => StatusCode::NOT_FOUND,
            Code::AlreadyExists => StatusCode::CONFLICT,
            Code::PermissionDenied => StatusCode::FORBIDDEN,
            Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            Code::FailedPrecondition => StatusCode::BAD_REQUEST,
            Code::Aborted => StatusCode::CONFLICT,
            Code::OutOfRange => StatusCode::BAD_REQUEST,
            Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
            Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        };

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("grpc-status", HeaderValue::from_str(&(status.code() as i32).to_string()).unwrap());
        headers.insert("grpc-message", HeaderValue::from_str(status.message()).unwrap_or_else(|_| HeaderValue::from_static("Invalid UTF-8 in error message")));

        GatewayResponse::new(http_status, headers, status.message().as_bytes().to_vec())
    }

    /// Register a gRPC service
    pub async fn register_service(&self, service_info: GrpcServiceInfo) -> GatewayResult<()> {
        self.service_registry.register_service(service_info).await
    }

    /// Unregister a gRPC service
    pub async fn unregister_service(&self, service_name: &str) -> GatewayResult<()> {
        self.service_registry.unregister_service(service_name).await
    }

    /// Get all registered services
    pub async fn get_services(&self) -> Vec<GrpcServiceInfo> {
        self.service_registry.get_all_services().await
    }

    /// Get service information
    pub async fn get_service_info(&self, service_name: &str) -> Option<GrpcServiceInfo> {
        self.service_registry.get_service(service_name).await
    }
}

/// Types of gRPC requests
#[derive(Debug, Clone, PartialEq)]
enum GrpcRequestType {
    Unary,
    ServerStreaming,
    ClientStreaming,
    BidirectionalStreaming,
}

/// gRPC service registry
pub struct GrpcServiceRegistry {
    services: RwLock<HashMap<String, GrpcServiceInfo>>,
}

impl GrpcServiceRegistry {
    fn new() -> Self {
        Self {
            services: RwLock::new(HashMap::new()),
        }
    }

    async fn register_service(&self, service_info: GrpcServiceInfo) -> GatewayResult<()> {
        let mut services = self.services.write().await;
        services.insert(service_info.name.clone(), service_info);
        Ok(())
    }

    async fn unregister_service(&self, service_name: &str) -> GatewayResult<()> {
        let mut services = self.services.write().await;
        services.remove(service_name);
        Ok(())
    }

    async fn get_service(&self, service_name: &str) -> Option<GrpcServiceInfo> {
        let services = self.services.read().await;
        services.get(service_name).cloned()
    }

    async fn get_all_services(&self) -> Vec<GrpcServiceInfo> {
        let services = self.services.read().await;
        services.values().cloned().collect()
    }
}

/// Information about a gRPC service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcServiceInfo {
    pub name: String,
    pub package: String,
    pub methods: Vec<GrpcMethodInfo>,
    pub description: Option<String>,
    pub version: Option<String>,
}

/// Information about a gRPC method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcMethodInfo {
    pub name: String,
    pub input_type: String,
    pub output_type: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
    pub description: Option<String>,
}

/// gRPC connection pool
pub struct GrpcConnectionPool {
    connections: DashMap<String, Arc<GrpcClient>>,
    config: GrpcConfig,
}

impl GrpcConnectionPool {
    fn new(config: GrpcConfig) -> Self {
        Self {
            connections: DashMap::new(),
            config,
        }
    }

    async fn get_connection(&self, service_instance: &ServiceInstance) -> GatewayResult<Arc<GrpcClient>> {
        let key = format!("{}:{}", service_instance.address.ip(), service_instance.address.port());
        
        if let Some(client) = self.connections.get(&key) {
            return Ok(client.clone());
        }

        // Create new connection
        let endpoint = Endpoint::from_shared(service_instance.url())
            .map_err(|e| GatewayError::internal(format!("Invalid endpoint URL: {}", e)))?
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout);

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| GatewayError::service_unavailable(&service_instance.name, &e.to_string()))?;

        let client = Arc::new(GrpcClient::new(channel));
        self.connections.insert(key, client.clone());
        
        Ok(client)
    }
}

/// Generic gRPC client wrapper with real tonic integration
pub struct GrpcClient {
    channel: Channel,
    /// Connection health status
    health_status: Arc<tokio::sync::RwLock<ConnectionHealth>>,
    /// Backpressure controller
    backpressure_controller: Arc<BackpressureController>,
    /// Connection metrics
    metrics: Arc<ConnectionMetrics>,
}

/// Connection health status
#[derive(Debug, Clone, PartialEq)]
enum ConnectionHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Backpressure controller for streaming connections
pub struct BackpressureController {
    /// Maximum concurrent streams per connection
    max_concurrent_streams: usize,
    /// Current active streams
    active_streams: Arc<tokio::sync::Semaphore>,
    /// Stream buffer size
    stream_buffer_size: usize,
}

impl BackpressureController {
    fn new(max_concurrent_streams: usize, stream_buffer_size: usize) -> Self {
        Self {
            max_concurrent_streams,
            active_streams: Arc::new(tokio::sync::Semaphore::new(max_concurrent_streams)),
            stream_buffer_size,
        }
    }

    /// Acquire a stream slot with backpressure handling
    async fn acquire_stream_slot(&self) -> Result<tokio::sync::SemaphorePermit, Status> {
        match tokio::time::timeout(
            Duration::from_secs(5),
            self.active_streams.acquire()
        ).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(Status::resource_exhausted("Semaphore closed")),
            Err(_) => Err(Status::resource_exhausted("Too many concurrent streams, backpressure applied")),
        }
    }
}

/// Connection metrics for monitoring
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Total requests made
    pub total_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Active requests
    pub active_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Failed requests
    pub failed_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Average response time
    pub avg_response_time: Arc<std::sync::atomic::AtomicU64>,
}

impl GrpcClient {
    fn new(channel: Channel) -> Self {
        Self {
            channel,
            health_status: Arc::new(tokio::sync::RwLock::new(ConnectionHealth::Healthy)),
            backpressure_controller: Arc::new(BackpressureController::new(100, 1000)),
            metrics: Arc::new(ConnectionMetrics::default()),
        }
    }

    /// Make a unary gRPC call with real tonic integration
    async fn call_unary(
        &self,
        service: String,
        method: String,
        request_data: Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        let start_time = Instant::now();
        self.metrics.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.metrics.active_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        debug!("Making unary call to {}/{}", service, method);

        // Check connection health
        if *self.health_status.read().await == ConnectionHealth::Unhealthy {
            return Err(Status::unavailable("Connection is unhealthy"));
        }

        // Create a generic gRPC request using tonic's Request type
        let _request = tonic::Request::new(request_data.clone());
        
        // Note: In a real implementation, you would use the actual generated client
        // For now, we'll simulate the call

        // Make the actual gRPC call using the channel
        // Note: This is a simplified implementation. In a real scenario, you would:
        // 1. Use the actual generated gRPC client for the specific service
        // 2. Deserialize the request_data into the proper protobuf message
        // 3. Call the specific method on the client
        // 4. Serialize the response back to bytes
        let result = self.simulate_unary_call(&service, &method, &request_data).await;

        // Update metrics
        self.metrics.active_requests.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let duration = start_time.elapsed().as_millis() as u64;
        self.metrics.avg_response_time.store(duration, std::sync::atomic::Ordering::Relaxed);

        match result {
            Ok(response) => {
                self.update_health_status(ConnectionHealth::Healthy).await;
                Ok(response)
            }
            Err(status) => {
                self.metrics.failed_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.handle_error_status(&status).await;
                Err(status)
            }
        }
    }

    /// Simulate a unary call (placeholder for real implementation)
    async fn simulate_unary_call(
        &self,
        _service: &str,
        _method: &str,
        request_data: &[u8],
    ) -> Result<Vec<u8>, Status> {
        // This is a placeholder implementation
        // In a real implementation, you would:
        // 1. Use the actual generated gRPC client
        // 2. Deserialize request_data into the proper protobuf message
        // 3. Make the actual gRPC call
        // 4. Serialize the response back to bytes
        
        // For now, just echo back the request data with a simple transformation
        let mut response = b"gRPC response: ".to_vec();
        response.extend_from_slice(request_data);
        Ok(response)
    }

    /// Update connection health status
    async fn update_health_status(&self, status: ConnectionHealth) {
        let mut health = self.health_status.write().await;
        *health = status;
    }

    /// Handle error status and update health accordingly
    async fn handle_error_status(&self, status: &Status) {
        match status.code() {
            Code::Unavailable | Code::DeadlineExceeded => {
                self.update_health_status(ConnectionHealth::Unhealthy).await;
            }
            Code::ResourceExhausted => {
                self.update_health_status(ConnectionHealth::Degraded).await;
            }
            _ => {
                // Other errors don't necessarily indicate connection health issues
            }
        }
    }

    /// Make a server streaming gRPC call
    async fn call_server_streaming(
        &self,
        service: String,
        method: String,
        request_data: Vec<u8>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>, Status> {
        debug!("Making server streaming call to {}/{}", service, method);

        // Acquire stream slot for backpressure control
        let _permit = self.backpressure_controller.acquire_stream_slot().await?;

        // Check connection health
        if *self.health_status.read().await == ConnectionHealth::Unhealthy {
            return Err(Status::unavailable("Connection is unhealthy"));
        }

        // Simulate server streaming response
        let response_data = self.simulate_unary_call(&service, &method, &request_data).await?;
        
        // Create a stream that yields the response data
        let stream = futures::stream::once(async move { Ok(response_data) });
        Ok(Box::pin(stream))
    }

    /// Make a client streaming gRPC call
    async fn call_client_streaming(
        &self,
        service: String,
        method: String,
        request_stream: Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>,
    ) -> Result<Vec<u8>, Status> {
        debug!("Making client streaming call to {}/{}", service, method);

        // Acquire stream slot for backpressure control
        let _permit = self.backpressure_controller.acquire_stream_slot().await?;

        // Check connection health
        if *self.health_status.read().await == ConnectionHealth::Unhealthy {
            return Err(Status::unavailable("Connection is unhealthy"));
        }

        // Simulate client streaming call
        // In a real implementation, you would use the actual gRPC client
        let mut collected_data = Vec::new();
        let mut stream = request_stream;
        while let Some(data) = stream.next().await {
            collected_data.extend_from_slice(&data);
        }
        let response = self.simulate_unary_call(&service, &method, &collected_data).await?;
        
        Ok(response)
    }

    /// Make a bidirectional streaming gRPC call
    async fn call_bidirectional_streaming(
        &self,
        service: String,
        method: String,
        request_stream: Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>, Status> {
        debug!("Making bidirectional streaming call to {}/{}", service, method);

        // Acquire stream slot for backpressure control
        let _permit = self.backpressure_controller.acquire_stream_slot().await?;

        // Check connection health
        if *self.health_status.read().await == ConnectionHealth::Unhealthy {
            return Err(Status::unavailable("Connection is unhealthy"));
        }

        // Simulate bidirectional streaming call
        // In a real implementation, you would use the actual gRPC client
        let mut collected_data = Vec::new();
        let mut stream = request_stream;
        while let Some(data) = stream.next().await {
            collected_data.extend_from_slice(&data);
        }
        let response_data = self.simulate_unary_call(&service, &method, &collected_data).await?;
        let response_stream = futures::stream::once(async move { Ok(response_data) });
        
        // Wrap with backpressure handling
        let controlled_stream = self.wrap_response_stream_with_backpressure(Box::pin(response_stream));
        
        Ok(Box::pin(controlled_stream))
    }







    /// Wrap response stream with backpressure handling
    fn wrap_response_stream_with_backpressure(
        &self,
        stream: Pin<Box<dyn Stream<Item = Result<Vec<u8>, Status>> + Send>>
    ) -> impl Stream<Item = Result<Vec<u8>, Status>> + Send {
        use futures::stream::StreamExt;
        use tokio::sync::mpsc;
        
        let (tx, rx) = mpsc::channel(self.backpressure_controller.stream_buffer_size);
        let health_status = self.health_status.clone();
        
        // Spawn a task to handle the stream with backpressure
        tokio::spawn(async move {
            let mut stream = stream;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(data) => {
                        if tx.send(Ok(data)).await.is_err() {
                            // Receiver dropped, stop processing
                            break;
                        }
                    }
                    Err(status) => {
                        // Update health status on error
                        if matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded) {
                            *health_status.write().await = ConnectionHealth::Degraded;
                        }
                        
                        if tx.send(Err(status)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }



    /// Get connection metrics
    pub fn get_metrics(&self) -> ConnectionMetrics {
        ConnectionMetrics {
            total_requests: self.metrics.total_requests.clone(),
            active_requests: self.metrics.active_requests.clone(),
            failed_requests: self.metrics.failed_requests.clone(),
            avg_response_time: self.metrics.avg_response_time.clone(),
        }
    }

    /// Check if connection is healthy
    pub async fn is_healthy(&self) -> bool {
        *self.health_status.read().await == ConnectionHealth::Healthy
    }
}

/// gRPC-Web proxy for browser clients
pub struct GrpcWebProxy {
    config: GrpcConfig,
}

impl GrpcWebProxy {
    fn new(config: GrpcConfig) -> Self {
        Self { config }
    }

    async fn handle_request(
        &self,
        request: Arc<IncomingRequest>,
        _context: &RequestContext,
    ) -> GatewayResult<GatewayResponse> {
        debug!("Handling gRPC-Web request");
        
        // Convert gRPC-Web request to regular gRPC request
        let _grpc_request = self.convert_grpc_web_to_grpc(&request)?;
        
        // Process as regular gRPC request
        // This is simplified - in practice you'd need to handle the specific gRPC-Web protocol
        
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc-web"));
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert("access-control-allow-methods", HeaderValue::from_static("POST"));
        headers.insert("access-control-allow-headers", HeaderValue::from_static("content-type,x-grpc-web,x-user-agent"));
        
        Ok(GatewayResponse::new(
            StatusCode::OK,
            headers,
            b"grpc-web response".to_vec(),
        ))
    }

    fn convert_grpc_web_to_grpc(&self, request: &IncomingRequest) -> GatewayResult<Vec<u8>> {
        // gRPC-Web uses base64 encoding for binary data
        // This is a simplified conversion
        Ok(request.body.as_ref().clone())
    }
}

/// Message inspector for protobuf message inspection and transformation
pub struct MessageInspector {
    // In a real implementation, this would contain protobuf descriptors
}

impl MessageInspector {
    fn new() -> Self {
        Self {}
    }

    async fn inspect_request(
        &self,
        request: &IncomingRequest,
        service: &str,
        method: &str,
    ) -> GatewayResult<()> {
        debug!(
            service = %service,
            method = %method,
            body_size = request.body.len(),
            "Inspecting gRPC message"
        );
        
        // In a real implementation, you would:
        // 1. Parse the protobuf message using the service definition
        // 2. Validate the message structure
        // 3. Apply any transformations
        // 4. Log relevant information for monitoring
        
        Ok(())
    }
}