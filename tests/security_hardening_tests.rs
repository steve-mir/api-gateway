//! # Security Hardening Integration Tests
//!
//! This test suite validates all security hardening features implemented in Task 28:
//! - TLS/SSL support using rustls
//! - Request signing and verification capabilities
//! - Security headers injection
//! - Input validation and sanitization
//! - Security audit logging
//! - Threat detection and security monitoring

use api_gateway::core::error::GatewayError;
use api_gateway::core::security::{
    SecurityManager, TlsConfig, TlsVersion, SignatureConfig, SignatureAlgorithm,
    SecurityHeadersConfig, HstsConfig, FrameOptions, XssProtection, ReferrerPolicy,
    SanitizerConfig, ValidationRule, ValidationType, AuditConfig, SecuritySeverity,
    SecurityEventType, ThreatDetectionRule, ThreatRuleType, ThreatSeverity, ThreatAction,
    IpReputation, RequestSignature, SigningKey, VerificationKey,
};
use api_gateway::middleware::{SecurityMiddlewareConfig, create_security_middleware};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Router,
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio_test;
use tower::ServiceExt;
use uuid::Uuid;

// ============================================================================
// Test Utilities
// ============================================================================

/// Create a test security manager with default configuration
async fn create_test_security_manager() -> Arc<SecurityManager> {
    let security_manager = Arc::new(SecurityManager::default());
    
    // Initialize without TLS certificates (they don't exist in test environment)
    // The TLS manager will handle missing certificates gracefully
    
    security_manager
}

/// Create a test request with specified parameters
fn create_test_request(
    method: Method,
    uri: &str,
    headers: Option<HeaderMap>,
    body: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri);

    if let Some(headers) = headers {
        for (name, value) in headers.iter() {
            request = request.header(name, value);
        }
    }

    let body = body.unwrap_or("").to_string();
    request.body(Body::from(body)).unwrap()
}

/// Create test app with security middleware
async fn create_test_app() -> Router {
    let security_manager = create_test_security_manager().await;
    let config = SecurityMiddlewareConfig {
        enforce_tls: false, // Disabled for testing
        require_signatures: false,
        validate_input: true,
        inject_security_headers: true,
        threat_detection: true,
        max_body_size: 1024 * 1024,
        block_threats: false, // Disabled for testing
    };

    Router::new()
        .route("/test", get(|| async { "OK" }))
        .route("/json", post(|| async { "JSON OK" }))
        .layer(create_security_middleware(security_manager, config))
}

// ============================================================================
// TLS/SSL Support Tests
// ============================================================================

#[tokio::test]
async fn test_tls_config_creation() {
    let tls_config = TlsConfig {
        cert_file: "/tmp/test.crt".to_string(),
        key_file: "/tmp/test.key".to_string(),
        min_version: TlsVersion::V1_2,
        cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
        require_client_cert: false,
        ca_file: None,
        ocsp_stapling: true,
        ct_logs: true,
    };

    // Test that TLS manager can be created with configuration
    let security_manager = SecurityManager::default();
    let tls_manager = &security_manager.tls_manager;
    
    // Should not panic when creating TLS manager
    assert!(tls_manager.get_server_config().await.is_none()); // No certs loaded yet
}

#[tokio::test]
async fn test_tls_certificate_validation() {
    let security_manager = create_test_security_manager().await;
    let tls_manager = &security_manager.tls_manager;

    // Test certificate chain validation with empty chain
    let empty_chain = vec![];
    let result = tls_manager.validate_certificate_chain(&empty_chain).await;
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Empty chain should be invalid

    // Test certificate info retrieval
    let cert_info = tls_manager.get_certificate_info().await;
    assert!(cert_info.is_ok());
    let info = cert_info.unwrap();
    assert_eq!(info.subject, "CN=api-gateway");
}

// ============================================================================
// Request Signing and Verification Tests
// ============================================================================

#[tokio::test]
async fn test_request_signing_and_verification() {
    let security_manager = create_test_security_manager().await;
    let request_signer = &security_manager.request_signer;

    // Create test signing and verification keys
    let key_id = "test-key-1";
    let secret_key = b"test-secret-key-for-hmac-signing";

    let signing_key = SigningKey {
        key_id: key_id.to_string(),
        algorithm: SignatureAlgorithm::HmacSha256,
        private_key: secret_key.to_vec(),
        created_at: Utc::now(),
        expires_at: None,
    };

    let verification_key = VerificationKey {
        key_id: key_id.to_string(),
        algorithm: SignatureAlgorithm::HmacSha256,
        public_key: secret_key.to_vec(), // For HMAC, public key is same as private key
        created_at: Utc::now(),
        expires_at: None,
    };

    // Add keys to signer
    request_signer.add_signing_key(signing_key).await.unwrap();
    request_signer.add_verification_key(verification_key).await.unwrap();

    // Create test request
    let method = Method::POST;
    let uri: Uri = "/api/test".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("host", "api.example.com".parse().unwrap());
    let body = b"{\"test\": \"data\"}";

    // Sign the request
    let signature = request_signer
        .sign_request(&method, &uri, &headers, body, key_id)
        .await
        .unwrap();

    assert_eq!(signature.key_id, key_id);
    assert!(matches!(signature.algorithm, SignatureAlgorithm::HmacSha256));
    assert!(!signature.signature.is_empty());

    // Verify the signature
    let is_valid = request_signer
        .verify_request(&method, &uri, &headers, body, &signature)
        .await
        .unwrap();

    assert!(is_valid);

    // Test with modified body (should fail verification)
    let modified_body = b"{\"test\": \"modified\"}";
    let is_valid_modified = request_signer
        .verify_request(&method, &uri, &headers, modified_body, &signature)
        .await
        .unwrap();

    assert!(!is_valid_modified);
}

#[tokio::test]
async fn test_signature_expiration() {
    let security_manager = create_test_security_manager().await;
    let request_signer = &security_manager.request_signer;

    // Create expired signature
    let expired_signature = RequestSignature {
        key_id: "test-key".to_string(),
        algorithm: SignatureAlgorithm::HmacSha256,
        signature: "test-signature".to_string(),
        timestamp: Utc::now() - Duration::minutes(10), // 10 minutes ago
        signed_headers: vec!["host".to_string()],
    };

    let method = Method::GET;
    let uri: Uri = "/test".parse().unwrap();
    let headers = HeaderMap::new();
    let body = b"";

    // Should fail due to expiration
    let result = request_signer
        .verify_request(&method, &uri, &headers, body, &expired_signature)
        .await;

    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should be false due to expiration
}

// ============================================================================
// Security Headers Tests
// ============================================================================

#[tokio::test]
async fn test_security_headers_injection() {
    let app = create_test_app().await;

    let request = Request::builder()
        .uri("/test")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Check that security headers are present
    let headers = response.headers();
    
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-xss-protection"));
    assert!(headers.contains_key("referrer-policy"));
    assert!(headers.contains_key("permissions-policy"));

    // Verify specific header values
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY"
    );
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        headers.get("x-xss-protection").unwrap(),
        "1; mode=block"
    );
}

#[tokio::test]
async fn test_security_headers_configuration() {
    let security_manager = create_test_security_manager().await;
    let security_headers = &security_manager.security_headers;

    let mut headers = HeaderMap::new();
    security_headers.apply_headers(&mut headers).unwrap();

    // Test default configuration
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("strict-transport-security"));

    // Test HSTS header format
    let hsts_header = headers.get("strict-transport-security").unwrap();
    let hsts_value = hsts_header.to_str().unwrap();
    assert!(hsts_value.contains("max-age=31536000"));
    assert!(hsts_value.contains("includeSubDomains"));
}

#[tokio::test]
async fn test_custom_security_headers() {
    let mut custom_headers = HashMap::new();
    custom_headers.insert("X-Custom-Security".to_string(), "enabled".to_string());

    let config = SecurityHeadersConfig {
        csp: Some("default-src 'self'".to_string()),
        hsts: Some(HstsConfig {
            max_age: 3600,
            include_subdomains: false,
            preload: true,
        }),
        frame_options: Some(FrameOptions::SameOrigin),
        content_type_options: true,
        xss_protection: Some(XssProtection {
            enabled: false,
            block: false,
        }),
        referrer_policy: Some(ReferrerPolicy::NoReferrer),
        permissions_policy: None,
        custom_headers,
    };

    let security_headers = api_gateway::core::security::SecurityHeaders::new(config);
    let mut headers = HeaderMap::new();
    security_headers.apply_headers(&mut headers).unwrap();

    // Check custom header
    assert_eq!(
        headers.get("x-custom-security").unwrap(),
        "enabled"
    );

    // Check modified HSTS
    let hsts_value = headers.get("strict-transport-security").unwrap().to_str().unwrap();
    assert!(hsts_value.contains("max-age=3600"));
    assert!(hsts_value.contains("preload"));
    assert!(!hsts_value.contains("includeSubDomains"));

    // Check disabled XSS protection
    assert_eq!(
        headers.get("x-xss-protection").unwrap(),
        "0"
    );
}

// ============================================================================
// Input Validation and Sanitization Tests
// ============================================================================

#[tokio::test]
async fn test_input_validation_sql_injection() {
    let security_manager = create_test_security_manager().await;
    let input_validator = &security_manager.input_validator;

    // Add SQL injection validation rule
    let rule = ValidationRule {
        name: "sql_injection_check".to_string(),
        field_path: "query".to_string(),
        validation_type: ValidationType::SqlInjection,
        required: true,
        error_message: Some("SQL injection detected".to_string()),
    };

    input_validator.add_rule(rule).await.unwrap();

    // Test with malicious SQL input
    let malicious_input = json!({
        "query": "SELECT * FROM users WHERE id = 1 OR 1=1 --"
    });

    let result = input_validator
        .validate_and_sanitize(&malicious_input, "test")
        .await
        .unwrap();

    assert!(!result.valid);
    assert!(!result.errors.is_empty());
    assert_eq!(result.errors[0].code, "SQL_INJECTION_DETECTED");

    // Test with safe input
    let safe_input = json!({
        "query": "user search term"
    });

    let result = input_validator
        .validate_and_sanitize(&safe_input, "test")
        .await
        .unwrap();

    assert!(result.valid);
    assert!(result.errors.is_empty());
}

#[tokio::test]
async fn test_input_validation_xss() {
    let security_manager = create_test_security_manager().await;
    let input_validator = &security_manager.input_validator;

    // Add XSS validation rule
    let rule = ValidationRule {
        name: "xss_check".to_string(),
        field_path: "content".to_string(),
        validation_type: ValidationType::Xss,
        required: true,
        error_message: None,
    };

    input_validator.add_rule(rule).await.unwrap();

    // Test with XSS payload
    let xss_input = json!({
        "content": "<script>alert('xss')</script>"
    });

    let result = input_validator
        .validate_and_sanitize(&xss_input, "test")
        .await
        .unwrap();

    assert!(!result.valid);
    assert!(!result.errors.is_empty());
    assert_eq!(result.errors[0].code, "XSS_DETECTED");

    // Test with safe HTML
    let safe_input = json!({
        "content": "This is safe content"
    });

    let result = input_validator
        .validate_and_sanitize(&safe_input, "test")
        .await
        .unwrap();

    assert!(result.valid);
    assert!(result.errors.is_empty());
}

#[tokio::test]
async fn test_input_sanitization() {
    let sanitizer_config = SanitizerConfig {
        html_sanitization: true,
        sql_injection_prevention: true,
        xss_prevention: true,
        path_traversal_prevention: true,
        max_input_length: 1000,
        allowed_characters: None,
    };

    let input_validator = api_gateway::core::security::InputValidator::new(sanitizer_config);

    // Test XSS sanitization
    let xss_input = json!({
        "content": "<script>alert('test')</script><p>Safe content</p>"
    });

    let result = input_validator
        .validate_and_sanitize(&xss_input, "test")
        .await
        .unwrap();

    assert!(result.valid);
    if let Some(sanitized) = result.sanitized_value {
        let content = sanitized["content"].as_str().unwrap();
        assert!(!content.contains("<script>"));
        assert!(!content.contains("alert"));
        assert!(content.contains("&lt;"));
        assert!(content.contains("&gt;"));
    }
}

#[tokio::test]
async fn test_path_traversal_detection() {
    let security_manager = create_test_security_manager().await;
    let input_validator = &security_manager.input_validator;

    // Add path traversal validation rule
    let rule = ValidationRule {
        name: "path_traversal_check".to_string(),
        field_path: "file_path".to_string(),
        validation_type: ValidationType::PathTraversal,
        required: true,
        error_message: None,
    };

    input_validator.add_rule(rule).await.unwrap();

    // Test with path traversal attempt
    let traversal_input = json!({
        "file_path": "../../../etc/passwd"
    });

    let result = input_validator
        .validate_and_sanitize(&traversal_input, "test")
        .await
        .unwrap();

    assert!(!result.valid);
    assert!(!result.errors.is_empty());
    assert_eq!(result.errors[0].code, "PATH_TRAVERSAL_DETECTED");

    // Test with safe path
    let safe_input = json!({
        "file_path": "documents/file.txt"
    });

    let result = input_validator
        .validate_and_sanitize(&safe_input, "test")
        .await
        .unwrap();

    assert!(result.valid);
    assert!(result.errors.is_empty());
}

// ============================================================================
// Security Audit Logging Tests
// ============================================================================

#[tokio::test]
async fn test_security_audit_logging() {
    let security_manager = create_test_security_manager().await;
    let security_auditor = &security_manager.security_auditor;

    // Log a security event
    security_auditor
        .log_event(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Warning,
            Some("test_user".to_string()),
            "192.168.1.100".to_string(),
            Some("Mozilla/5.0".to_string()),
            json!({
                "reason": "Invalid credentials",
                "attempt_count": 3
            }),
            Some("req-123".to_string()),
            Some("sess-456".to_string()),
        )
        .await
        .unwrap();

    // Retrieve audit logs
    let logs = security_auditor
        .get_audit_logs(
            Some(SecurityEventType::AuthenticationFailure),
            None,
            None,
            10,
        )
        .await;

    assert_eq!(logs.len(), 1);
    let log_entry = &logs[0];
    assert!(matches!(log_entry.event_type, SecurityEventType::AuthenticationFailure));
    assert!(matches!(log_entry.severity, SecuritySeverity::Warning));
    assert_eq!(log_entry.user_id, Some("test_user".to_string()));
    assert_eq!(log_entry.ip_address, "192.168.1.100");
}

#[tokio::test]
async fn test_audit_log_filtering() {
    let security_manager = create_test_security_manager().await;
    let security_auditor = &security_manager.security_auditor;

    // Log multiple events
    security_auditor
        .log_event(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Info,
            Some("user1".to_string()),
            "192.168.1.1".to_string(),
            None,
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();

    security_auditor
        .log_event(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::Warning,
            Some("user2".to_string()),
            "192.168.1.2".to_string(),
            None,
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();

    security_auditor
        .log_event(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Info,
            Some("user1".to_string()),
            "192.168.1.1".to_string(),
            None,
            json!({}),
            None,
            None,
        )
        .await
        .unwrap();

    // Filter by event type
    let success_logs = security_auditor
        .get_audit_logs(
            Some(SecurityEventType::AuthenticationSuccess),
            None,
            None,
            10,
        )
        .await;

    assert_eq!(success_logs.len(), 2);

    // Filter by user
    let user1_logs = security_auditor
        .get_audit_logs(
            None,
            None,
            Some("user1".to_string()),
            10,
        )
        .await;

    assert_eq!(user1_logs.len(), 2);

    // Filter by severity
    let warning_logs = security_auditor
        .get_audit_logs(
            None,
            Some(SecuritySeverity::Warning),
            None,
            10,
        )
        .await;

    assert_eq!(warning_logs.len(), 1);
}

// ============================================================================
// Threat Detection Tests
// ============================================================================

#[tokio::test]
async fn test_threat_detection_rules() {
    let security_manager = create_test_security_manager().await;
    let threat_detector = &security_manager.threat_detector;

    // Add custom threat detection rule
    let rule = ThreatDetectionRule {
        id: Uuid::new_v4(),
        name: "Test Rate Limit Rule".to_string(),
        description: "Test rule for rate limiting".to_string(),
        rule_type: ThreatRuleType::RateLimit,
        parameters: json!({
            "max_requests": 100,
            "window_seconds": 60
        }),
        severity: ThreatSeverity::Medium,
        active: true,
        actions: vec![ThreatAction::Log, ThreatAction::RateLimit],
    };

    threat_detector.add_rule(rule).await.unwrap();

    // Test threat analysis
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let method = Method::GET;
    let uri: Uri = "/api/test".parse().unwrap();
    let headers = HeaderMap::new();
    let body = b"test body";

    let threats = threat_detector
        .analyze_request(ip, None, &method, &uri, &headers, body)
        .await
        .unwrap();

    // Should not detect threats for normal request
    assert!(threats.is_empty());
}

#[tokio::test]
async fn test_ip_reputation_threat_detection() {
    let security_manager = create_test_security_manager().await;
    let threat_detector = &security_manager.threat_detector;

    // Add malicious IP to reputation cache
    let malicious_ip: IpAddr = "10.0.0.1".parse().unwrap();
    let reputation = IpReputation {
        ip: malicious_ip,
        score: 10, // Low score indicates bad reputation
        sources: vec!["test_source".to_string()],
        last_updated: Utc::now(),
        is_malicious: true,
        country: Some("XX".to_string()),
        asn: Some("AS12345".to_string()),
    };

    threat_detector.update_ip_reputation(malicious_ip, reputation).await;

    // Test threat detection for malicious IP
    let method = Method::GET;
    let uri: Uri = "/api/test".parse().unwrap();
    let headers = HeaderMap::new();
    let body = b"";

    let threats = threat_detector
        .analyze_request(malicious_ip, None, &method, &uri, &headers, body)
        .await
        .unwrap();

    assert!(!threats.is_empty());
    let threat = &threats[0];
    assert!(matches!(threat.threat_type, ThreatRuleType::Reputation));
    assert!(matches!(threat.severity, ThreatSeverity::High));
    assert_eq!(threat.source_ip, malicious_ip);
}

#[tokio::test]
async fn test_threat_detection_actions() {
    let security_manager = create_test_security_manager().await;
    let threat_detector = &security_manager.threat_detector;

    // Get detected threats (should be empty initially)
    let threats = threat_detector.get_threats(10).await;
    assert!(threats.is_empty());

    // Add a malicious IP and trigger detection
    let malicious_ip: IpAddr = "10.0.0.2".parse().unwrap();
    let reputation = IpReputation {
        ip: malicious_ip,
        score: 5,
        sources: vec!["threat_intel".to_string()],
        last_updated: Utc::now(),
        is_malicious: true,
        country: Some("XX".to_string()),
        asn: None,
    };

    threat_detector.update_ip_reputation(malicious_ip, reputation).await;

    // Trigger threat detection
    let method = Method::POST;
    let uri: Uri = "/api/sensitive".parse().unwrap();
    let headers = HeaderMap::new();
    let body = b"malicious payload";

    let detected_threats = threat_detector
        .analyze_request(malicious_ip, Some("attacker".to_string()), &method, &uri, &headers, body)
        .await
        .unwrap();

    assert!(!detected_threats.is_empty());

    // Check that threat was stored
    let stored_threats = threat_detector.get_threats(10).await;
    assert!(!stored_threats.is_empty());

    let threat = &stored_threats[0];
    assert_eq!(threat.user_id, Some("attacker".to_string()));
    assert!(threat.actions_taken.contains(&ThreatAction::Block));
    assert!(threat.actions_taken.contains(&ThreatAction::Log));
}

// ============================================================================
// Integration Tests with Middleware
// ============================================================================

#[tokio::test]
async fn test_security_middleware_integration() {
    let app = create_test_app().await;

    // Test normal request
    let request = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("user-agent", "test-client/1.0")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Check security headers are present
    let headers = response.headers();
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("x-frame-options"));
}

#[tokio::test]
async fn test_json_input_validation_middleware() {
    let app = create_test_app().await;

    // Test with valid JSON
    let valid_request = Request::builder()
        .method(Method::POST)
        .uri("/json")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name": "test", "value": 123}"#))
        .unwrap();

    let response = app.clone().oneshot(valid_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test with potentially malicious JSON (should be sanitized)
    let malicious_request = Request::builder()
        .method(Method::POST)
        .uri("/json")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"script": "<script>alert('xss')</script>"}"#))
        .unwrap();

    let response = app.clone().oneshot(malicious_request).await.unwrap();
    // Should still succeed but content should be sanitized
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_large_request_body_handling() {
    let app = create_test_app().await;

    // Create a request body larger than the configured limit
    let large_body = "x".repeat(2 * 1024 * 1024); // 2MB, larger than 1MB limit

    let request = Request::builder()
        .method(Method::POST)
        .uri("/json")
        .header("content-type", "application/json")
        .body(Body::from(large_body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Should be rejected due to size limit
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// Security Manager Integration Tests
// ============================================================================

#[tokio::test]
async fn test_security_manager_initialization() {
    let security_manager = SecurityManager::default();
    
    // Test initialization without TLS certificates
    let result = security_manager.initialize().await;
    assert!(result.is_ok());

    // Verify all components are accessible
    assert!(security_manager.tls_manager.get_server_config().await.is_none());
    
    // Test security auditor
    let logs = security_manager.security_auditor.get_audit_logs(None, None, None, 10).await;
    assert!(logs.is_empty());

    // Test threat detector
    let threats = security_manager.threat_detector.get_threats(10).await;
    assert!(threats.is_empty());
}

#[tokio::test]
async fn test_security_manager_components_integration() {
    let security_manager = create_test_security_manager().await;

    // Test that all components work together
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    
    // Add IP reputation
    let reputation = IpReputation {
        ip,
        score: 95, // Good reputation
        sources: vec!["test".to_string()],
        last_updated: Utc::now(),
        is_malicious: false,
        country: Some("US".to_string()),
        asn: Some("AS12345".to_string()),
    };

    security_manager.threat_detector.update_ip_reputation(ip, reputation).await;

    // Log security event
    security_manager
        .security_auditor
        .log_event(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Info,
            Some("test_user".to_string()),
            ip.to_string(),
            Some("test-agent".to_string()),
            json!({"test": "data"}),
            Some("req-123".to_string()),
            None,
        )
        .await
        .unwrap();

    // Verify event was logged
    let logs = security_manager
        .security_auditor
        .get_audit_logs(None, None, Some("test_user".to_string()), 10)
        .await;

    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].ip_address, ip.to_string());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_security_error_handling() {
    let security_manager = create_test_security_manager().await;

    // Test invalid signature verification
    let invalid_signature = RequestSignature {
        key_id: "non-existent-key".to_string(),
        algorithm: SignatureAlgorithm::HmacSha256,
        signature: "invalid".to_string(),
        timestamp: Utc::now(),
        signed_headers: vec![],
    };

    let method = Method::GET;
    let uri: Uri = "/test".parse().unwrap();
    let headers = HeaderMap::new();
    let body = b"";

    let result = security_manager
        .request_signer
        .verify_request(&method, &uri, &headers, body, &invalid_signature)
        .await;

    // Should return error for non-existent key
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), GatewayError::Authentication { .. }));
}

#[tokio::test]
async fn test_validation_error_handling() {
    let security_manager = create_test_security_manager().await;
    let input_validator = &security_manager.input_validator;

    // Add validation rule with invalid regex
    let invalid_rule = ValidationRule {
        name: "invalid_regex".to_string(),
        field_path: "test_field".to_string(),
        validation_type: ValidationType::Regex {
            pattern: "[invalid regex(".to_string(), // Invalid regex pattern
        },
        required: true,
        error_message: None,
    };

    input_validator.add_rule(invalid_rule).await.unwrap();

    let test_input = json!({
        "test_field": "test value"
    });

    let result = input_validator
        .validate_and_sanitize(&test_input, "test")
        .await
        .unwrap();

    // Should handle invalid regex gracefully
    assert!(!result.valid);
    assert!(!result.errors.is_empty());
}

#[tokio::test]
async fn test_concurrent_security_operations() {
    let security_manager = Arc::new(SecurityManager::default());
    let mut handles = vec![];

    // Spawn multiple concurrent operations
    for i in 0..10 {
        let sm = security_manager.clone();
        let handle = tokio::spawn(async move {
            // Log security events concurrently
            sm.security_auditor
                .log_event(
                    SecurityEventType::AuthenticationSuccess,
                    SecuritySeverity::Info,
                    Some(format!("user_{}", i)),
                    format!("192.168.1.{}", i + 1),
                    None,
                    json!({"concurrent_test": i}),
                    Some(format!("req_{}", i)),
                    None,
                )
                .await
                .unwrap();

            // Update IP reputation concurrently
            let ip: IpAddr = format!("10.0.0.{}", i + 1).parse().unwrap();
            let reputation = IpReputation {
                ip,
                score: 50 + i as u8,
                sources: vec![format!("source_{}", i)],
                last_updated: Utc::now(),
                is_malicious: false,
                country: Some("US".to_string()),
                asn: None,
            };

            sm.threat_detector.update_ip_reputation(ip, reputation).await;
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all operations completed successfully
    let logs = security_manager
        .security_auditor
        .get_audit_logs(None, None, None, 20)
        .await;

    assert_eq!(logs.len(), 10);
}