//! # Security Hardening Demo
//!
//! This example demonstrates the security hardening features implemented in Task 28:
//! - TLS/SSL support using rustls
//! - Request signing and verification capabilities
//! - Security headers injection
//! - Input validation and sanitization
//! - Security audit logging
//! - Threat detection and security monitoring

use api_gateway::core::security::{
    SecurityManager, TlsConfig, TlsVersion, SignatureConfig, SignatureAlgorithm,
    SecurityHeadersConfig, HstsConfig, FrameOptions, XssProtection, ReferrerPolicy,
    SanitizerConfig, ValidationRule, ValidationType, AuditConfig, SecuritySeverity,
    SecurityEventType, ThreatDetectionRule, ThreatRuleType, ThreatSeverity, ThreatAction,
    IpReputation, RequestSignature, SigningKey, VerificationKey,
};
use axum::http::{HeaderMap, Method, Uri};
use chrono::{Duration, Utc};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::init();

    println!("🔒 Security Hardening Demo - Task 28 Implementation");
    println!("==================================================");

    // 1. Create Security Manager
    println!("\n1. Creating Security Manager...");
    let security_manager = SecurityManager::default();
    security_manager.initialize().await?;
    println!("✅ Security Manager initialized successfully");

    // 2. Demonstrate TLS Configuration
    println!("\n2. TLS/SSL Configuration...");
    let tls_config = TlsConfig {
        cert_file: "/etc/ssl/certs/gateway.crt".to_string(),
        key_file: "/etc/ssl/private/gateway.key".to_string(),
        min_version: TlsVersion::V1_2,
        cipher_suites: vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        ],
        require_client_cert: false,
        ca_file: None,
        ocsp_stapling: true,
        ct_logs: true,
    };
    println!("✅ TLS configuration created (certificates would be loaded in production)");

    // 3. Demonstrate Request Signing
    println!("\n3. Request Signing and Verification...");
    let key_id = "demo-key-1";
    let secret_key = b"demo-secret-key-for-hmac-signing-example";

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
        public_key: secret_key.to_vec(),
        created_at: Utc::now(),
        expires_at: None,
    };

    security_manager.request_signer.add_signing_key(signing_key).await?;
    security_manager.request_signer.add_verification_key(verification_key).await?;

    // Sign a test request
    let method = Method::POST;
    let uri: Uri = "/api/secure-endpoint".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert("host", "api.example.com".parse().unwrap());
    let body = b"{\"message\": \"Hello, secure world!\"}";

    let signature = security_manager
        .request_signer
        .sign_request(&method, &uri, &headers, body, key_id)
        .await?;

    println!("✅ Request signed successfully");
    println!("   Algorithm: {:?}", signature.algorithm);
    println!("   Key ID: {}", signature.key_id);
    println!("   Signature: {}...", &signature.signature[..20]);

    // Verify the signature
    let is_valid = security_manager
        .request_signer
        .verify_request(&method, &uri, &headers, body, &signature)
        .await?;

    println!("✅ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // 4. Demonstrate Security Headers
    println!("\n4. Security Headers Injection...");
    let mut response_headers = HeaderMap::new();
    security_manager.security_headers.apply_headers(&mut response_headers)?;

    println!("✅ Security headers applied:");
    for (name, value) in response_headers.iter() {
        println!("   {}: {}", name, value.to_str().unwrap_or("<invalid>"));
    }

    // 5. Demonstrate Input Validation
    println!("\n5. Input Validation and Sanitization...");
    
    // Add validation rules
    let sql_injection_rule = ValidationRule {
        name: "sql_injection_check".to_string(),
        field_path: "query".to_string(),
        validation_type: ValidationType::SqlInjection,
        required: true,
        error_message: Some("SQL injection detected".to_string()),
    };

    let xss_rule = ValidationRule {
        name: "xss_check".to_string(),
        field_path: "content".to_string(),
        validation_type: ValidationType::Xss,
        required: false,
        error_message: None,
    };

    security_manager.input_validator.add_rule(sql_injection_rule).await?;
    security_manager.input_validator.add_rule(xss_rule).await?;

    // Test with malicious input
    let malicious_input = json!({
        "query": "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "content": "<script>alert('xss')</script>Hello World"
    });

    let validation_result = security_manager
        .input_validator
        .validate_and_sanitize(&malicious_input, "demo")
        .await?;

    println!("✅ Input validation completed:");
    println!("   Valid: {}", validation_result.valid);
    if !validation_result.errors.is_empty() {
        println!("   Errors detected:");
        for error in &validation_result.errors {
            println!("     - {}: {} ({})", error.field, error.message, error.code);
        }
    }

    // Test with safe input
    let safe_input = json!({
        "query": "user search term",
        "content": "This is safe content"
    });

    let safe_validation = security_manager
        .input_validator
        .validate_and_sanitize(&safe_input, "demo")
        .await?;

    println!("   Safe input validation: {}", if safe_validation.valid { "PASSED" } else { "FAILED" });

    // 6. Demonstrate Security Audit Logging
    println!("\n6. Security Audit Logging...");
    
    // Log various security events
    security_manager
        .security_auditor
        .log_event(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Info,
            Some("demo_user".to_string()),
            "192.168.1.100".to_string(),
            Some("SecurityDemo/1.0".to_string()),
            json!({
                "demo": true,
                "feature": "audit_logging"
            }),
            Some("demo-req-123".to_string()),
            Some("demo-sess-456".to_string()),
        )
        .await?;

    security_manager
        .security_auditor
        .log_event(
            SecurityEventType::InputValidationFailure,
            SecuritySeverity::Warning,
            Some("demo_user".to_string()),
            "192.168.1.100".to_string(),
            Some("SecurityDemo/1.0".to_string()),
            json!({
                "validation_errors": validation_result.errors,
                "input_type": "malicious"
            }),
            Some("demo-req-124".to_string()),
            None,
        )
        .await?;

    // Retrieve audit logs
    let audit_logs = security_manager
        .security_auditor
        .get_audit_logs(None, None, Some("demo_user".to_string()), 10)
        .await;

    println!("✅ Security audit logging completed:");
    println!("   Total events logged: {}", audit_logs.len());
    for log in &audit_logs {
        println!("   - {:?} at {} ({})", log.event_type, log.timestamp.format("%H:%M:%S"), log.ip_address);
    }

    // 7. Demonstrate Threat Detection
    println!("\n7. Threat Detection and Monitoring...");
    
    // Add a malicious IP to reputation cache
    let malicious_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let reputation = IpReputation {
        ip: malicious_ip,
        score: 15, // Low score indicates bad reputation
        sources: vec!["demo_threat_intel".to_string()],
        last_updated: Utc::now(),
        is_malicious: true,
        country: Some("XX".to_string()),
        asn: Some("AS12345".to_string()),
    };

    security_manager.threat_detector.update_ip_reputation(malicious_ip, reputation).await;

    // Analyze a request from the malicious IP
    let threats = security_manager
        .threat_detector
        .analyze_request(
            malicious_ip,
            Some("suspicious_user".to_string()),
            &Method::GET,
            &"/api/sensitive".parse().unwrap(),
            &HeaderMap::new(),
            b"suspicious payload",
        )
        .await?;

    println!("✅ Threat detection completed:");
    if threats.is_empty() {
        println!("   No threats detected");
    } else {
        println!("   Threats detected: {}", threats.len());
        for threat in &threats {
            println!("   - {:?} threat from {} (severity: {:?})", 
                threat.threat_type, threat.source_ip, threat.severity);
            println!("     Actions: {:?}", threat.actions_taken);
        }
    }

    // Test with a good IP
    let good_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let good_reputation = IpReputation {
        ip: good_ip,
        score: 95, // High score indicates good reputation
        sources: vec!["demo_whitelist".to_string()],
        last_updated: Utc::now(),
        is_malicious: false,
        country: Some("US".to_string()),
        asn: Some("AS54321".to_string()),
    };

    security_manager.threat_detector.update_ip_reputation(good_ip, good_reputation).await;

    let good_threats = security_manager
        .threat_detector
        .analyze_request(
            good_ip,
            Some("legitimate_user".to_string()),
            &Method::GET,
            &"/api/public".parse().unwrap(),
            &HeaderMap::new(),
            b"normal request",
        )
        .await?;

    println!("   Good IP analysis: {} threats detected", good_threats.len());

    // 8. Summary
    println!("\n🎉 Security Hardening Demo Complete!");
    println!("=====================================");
    println!("✅ TLS/SSL configuration support");
    println!("✅ Request signing and verification");
    println!("✅ Security headers injection");
    println!("✅ Input validation and sanitization");
    println!("✅ Security audit logging");
    println!("✅ Threat detection and monitoring");
    println!("\nAll security hardening features from Task 28 have been successfully implemented!");

    Ok(())
}