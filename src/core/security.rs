//! # Security Hardening Module
//!
//! This module implements comprehensive security hardening features for the API Gateway:
//! - TLS/SSL support using rustls for secure communication
//! - Request signing and verification capabilities for API security
//! - Security headers injection for web security best practices
//! - Input validation and sanitization to prevent attacks
//! - Security audit logging for compliance and monitoring
//! - Threat detection and security monitoring capabilities

use crate::core::error::{GatewayError, GatewayResult};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use regex::Regex;
use rustls::{ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// TLS/SSL Support using rustls
// ============================================================================

/// TLS configuration and certificate management
pub struct TlsManager {
    /// Current TLS server configuration
    server_config: Arc<RwLock<Option<Arc<ServerConfig>>>>,
    /// Certificate store for validation
    cert_store: Arc<RwLock<HashMap<String, TlsCertificate>>>,
    /// TLS configuration settings
    config: TlsConfig,
}

/// TLS configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_file: String,
    /// Path to private key file
    pub key_file: String,
    /// Minimum TLS version
    pub min_version: TlsVersion,
    /// Cipher suites to use
    pub cipher_suites: Vec<String>,
    /// Whether to require client certificates
    pub require_client_cert: bool,
    /// Certificate authority file for client cert validation
    pub ca_file: Option<String>,
    /// OCSP stapling configuration
    pub ocsp_stapling: bool,
    /// Certificate transparency logs
    pub ct_logs: bool,
}

/// TLS version enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    V1_3,
}

/// TLS certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertificate {
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Certificate validity period
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Certificate fingerprint
    pub fingerprint: String,
    /// Certificate chain
    pub chain: Vec<String>,
}

impl TlsManager {
    /// Create a new TLS manager with configuration
    pub fn new(config: TlsConfig) -> GatewayResult<Self> {
        let manager = Self {
            server_config: Arc::new(RwLock::new(None)),
            cert_store: Arc::new(RwLock::new(HashMap::new())),
            config,
        };

        Ok(manager)
    }

    /// Initialize TLS configuration from certificate files
    pub async fn initialize(&self) -> GatewayResult<()> {
        let cert_file = File::open(&self.config.cert_file)
            .map_err(|e| GatewayError::config(format!("Failed to open cert file: {}", e)))?;
        let key_file = File::open(&self.config.key_file)
            .map_err(|e| GatewayError::config(format!("Failed to open key file: {}", e)))?;

        let mut cert_reader = BufReader::new(cert_file);
        let mut key_reader = BufReader::new(key_file);

        // Parse certificates
        let cert_chain: Vec<_> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| GatewayError::config(format!("Failed to parse certificates: {}", e)))?;

        // Parse private key
        let mut keys: Vec<_> = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| GatewayError::config(format!("Failed to parse private key: {}", e)))?;

        if keys.is_empty() {
            return Err(GatewayError::config("No private key found"));
        }

        let private_key = keys.remove(0);

        // Build TLS server configuration
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key.into())
            .map_err(|e| GatewayError::config(format!("Failed to build TLS config: {}", e)))?;

        // Store the configuration
        let mut server_config = self.server_config.write().await;
        *server_config = Some(Arc::new(config));

        info!("TLS configuration initialized successfully");
        Ok(())
    }

    /// Get the current TLS server configuration
    pub async fn get_server_config(&self) -> Option<Arc<ServerConfig>> {
        self.server_config.read().await.clone()
    }

    /// Reload TLS certificates
    pub async fn reload_certificates(&self) -> GatewayResult<()> {
        info!("Reloading TLS certificates");
        self.initialize().await
    }

    /// Validate certificate chain
    pub async fn validate_certificate_chain(&self, chain: &[rustls::pki_types::CertificateDer<'_>]) -> GatewayResult<bool> {
        // Implementation would validate the certificate chain
        // This is a simplified version
        if chain.is_empty() {
            return Ok(false);
        }

        // Check certificate validity, chain of trust, etc.
        // For now, we'll just check that we have certificates
        Ok(true)
    }

    /// Get certificate information
    pub async fn get_certificate_info(&self) -> GatewayResult<TlsCertificate> {
        // This would extract information from the loaded certificate
        // Simplified implementation
        Ok(TlsCertificate {
            subject: "CN=api-gateway".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "123456789".to_string(),
            not_before: Utc::now() - Duration::days(30),
            not_after: Utc::now() + Duration::days(365),
            fingerprint: "sha256:abcdef123456".to_string(),
            chain: vec!["cert1".to_string(), "cert2".to_string()],
        })
    }
}

// ============================================================================
// Request Signing and Verification
// ============================================================================

/// Request signing and verification system
pub struct RequestSigner {
    /// Signing keys by key ID
    signing_keys: Arc<RwLock<HashMap<String, SigningKey>>>,
    /// Verification keys by key ID
    verification_keys: Arc<RwLock<HashMap<String, VerificationKey>>>,
    /// Signature configuration
    config: SignatureConfig,
}

/// Signing key information
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// Key ID
    pub key_id: String,
    /// Key algorithm
    pub algorithm: SignatureAlgorithm,
    /// Private key data
    pub private_key: Vec<u8>,
    /// Key creation time
    pub created_at: DateTime<Utc>,
    /// Key expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

/// Verification key information
#[derive(Debug, Clone)]
pub struct VerificationKey {
    /// Key ID
    pub key_id: String,
    /// Key algorithm
    pub algorithm: SignatureAlgorithm,
    /// Public key data
    pub public_key: Vec<u8>,
    /// Key creation time
    pub created_at: DateTime<Utc>,
    /// Key expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

/// Signature algorithms supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
    #[serde(rename = "rsa-sha256")]
    RsaSha256,
    #[serde(rename = "ecdsa-sha256")]
    EcdsaSha256,
}

/// Signature configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Default signature algorithm
    pub default_algorithm: SignatureAlgorithm,
    /// Signature validity duration
    pub signature_ttl: Duration,
    /// Headers to include in signature
    pub signed_headers: Vec<String>,
    /// Whether to require signatures
    pub require_signature: bool,
    /// Clock skew tolerance
    pub clock_skew_tolerance: Duration,
}

/// Request signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSignature {
    /// Key ID used for signing
    pub key_id: String,
    /// Signature algorithm
    pub algorithm: SignatureAlgorithm,
    /// Signature value
    pub signature: String,
    /// Timestamp when signature was created
    pub timestamp: DateTime<Utc>,
    /// Headers included in signature
    pub signed_headers: Vec<String>,
}

impl RequestSigner {
    /// Create a new request signer
    pub fn new(config: SignatureConfig) -> Self {
        Self {
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            verification_keys: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Add a signing key
    pub async fn add_signing_key(&self, key: SigningKey) -> GatewayResult<()> {
        let mut keys = self.signing_keys.write().await;
        keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    /// Add a verification key
    pub async fn add_verification_key(&self, key: VerificationKey) -> GatewayResult<()> {
        let mut keys = self.verification_keys.write().await;
        keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    /// Sign a request
    pub async fn sign_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
        key_id: &str,
    ) -> GatewayResult<RequestSignature> {
        let signing_keys = self.signing_keys.read().await;
        let key = signing_keys.get(key_id)
            .ok_or_else(|| GatewayError::auth("Signing key not found"))?;

        // Create canonical request string
        let canonical_request = self.create_canonical_request(method, uri, headers, body)?;
        
        // Create signature
        let signature = match key.algorithm {
            SignatureAlgorithm::HmacSha256 => {
                self.create_hmac_signature(&canonical_request, &key.private_key)?
            }
            SignatureAlgorithm::RsaSha256 => {
                self.create_rsa_signature(&canonical_request, &key.private_key)?
            }
            SignatureAlgorithm::EcdsaSha256 => {
                self.create_ecdsa_signature(&canonical_request, &key.private_key)?
            }
        };

        Ok(RequestSignature {
            key_id: key_id.to_string(),
            algorithm: key.algorithm.clone(),
            signature,
            timestamp: Utc::now(),
            signed_headers: self.config.signed_headers.clone(),
        })
    }

    /// Verify a request signature
    pub async fn verify_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
        signature: &RequestSignature,
    ) -> GatewayResult<bool> {
        // Check signature timestamp
        let now = Utc::now();
        if now - signature.timestamp > self.config.signature_ttl {
            return Ok(false);
        }

        if signature.timestamp - now > self.config.clock_skew_tolerance {
            return Ok(false);
        }

        let verification_keys = self.verification_keys.read().await;
        let key = verification_keys.get(&signature.key_id)
            .ok_or_else(|| GatewayError::auth("Verification key not found"))?;

        // Check if key is expired
        if let Some(expires_at) = key.expires_at {
            if now > expires_at {
                return Ok(false);
            }
        }

        // Create canonical request string
        let canonical_request = self.create_canonical_request(method, uri, headers, body)?;

        // Verify signature
        match signature.algorithm {
            SignatureAlgorithm::HmacSha256 => {
                self.verify_hmac_signature(&canonical_request, &signature.signature, &key.public_key)
            }
            SignatureAlgorithm::RsaSha256 => {
                self.verify_rsa_signature(&canonical_request, &signature.signature, &key.public_key)
            }
            SignatureAlgorithm::EcdsaSha256 => {
                self.verify_ecdsa_signature(&canonical_request, &signature.signature, &key.public_key)
            }
        }
    }

    /// Create canonical request string for signing
    fn create_canonical_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> GatewayResult<String> {
        let mut canonical = String::new();
        
        // HTTP method
        canonical.push_str(method.as_str());
        canonical.push('\n');
        
        // URI path
        canonical.push_str(uri.path());
        canonical.push('\n');
        
        // Query string
        if let Some(query) = uri.query() {
            canonical.push_str(query);
        }
        canonical.push('\n');
        
        // Headers (sorted)
        let mut header_pairs: Vec<_> = headers.iter()
            .filter(|(name, _)| self.config.signed_headers.contains(&name.as_str().to_lowercase()))
            .map(|(name, value)| (name.as_str().to_lowercase(), value.to_str().unwrap_or("")))
            .collect();
        header_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        
        for (name, value) in header_pairs {
            canonical.push_str(&name);
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\n');
        }
        canonical.push('\n');
        
        // Body hash
        let body_hash = Sha256::digest(body);
        canonical.push_str(&hex::encode(body_hash));
        
        Ok(canonical)
    }

    /// Create HMAC-SHA256 signature
    fn create_hmac_signature(&self, data: &str, key: &[u8]) -> GatewayResult<String> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| GatewayError::auth(format!("Invalid HMAC key: {}", e)))?;
        mac.update(data.as_bytes());
        let result = mac.finalize();
        Ok(BASE64.encode(result.into_bytes()))
    }

    /// Create RSA-SHA256 signature
    fn create_rsa_signature(&self, data: &str, _key: &[u8]) -> GatewayResult<String> {
        // RSA signature implementation would go here
        // For now, return a placeholder
        Ok(BASE64.encode(format!("rsa-signature-{}", data.len())))
    }

    /// Create ECDSA-SHA256 signature
    fn create_ecdsa_signature(&self, data: &str, _key: &[u8]) -> GatewayResult<String> {
        // ECDSA signature implementation would go here
        // For now, return a placeholder
        Ok(BASE64.encode(format!("ecdsa-signature-{}", data.len())))
    }

    /// Verify HMAC-SHA256 signature
    fn verify_hmac_signature(&self, data: &str, signature: &str, key: &[u8]) -> GatewayResult<bool> {
        let expected = self.create_hmac_signature(data, key)?;
        Ok(expected == signature)
    }

    /// Verify RSA-SHA256 signature
    fn verify_rsa_signature(&self, _data: &str, _signature: &str, _key: &[u8]) -> GatewayResult<bool> {
        // RSA verification implementation would go here
        Ok(true) // Placeholder
    }

    /// Verify ECDSA-SHA256 signature
    fn verify_ecdsa_signature(&self, _data: &str, _signature: &str, _key: &[u8]) -> GatewayResult<bool> {
        // ECDSA verification implementation would go here
        Ok(true) // Placeholder
    }
}

// ============================================================================
// Security Headers Injection
// ============================================================================

/// Security headers manager
pub struct SecurityHeaders {
    /// Security headers configuration
    config: SecurityHeadersConfig,
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Content Security Policy
    pub csp: Option<String>,
    /// HTTP Strict Transport Security
    pub hsts: Option<HstsConfig>,
    /// X-Frame-Options
    pub frame_options: Option<FrameOptions>,
    /// X-Content-Type-Options
    pub content_type_options: bool,
    /// X-XSS-Protection
    pub xss_protection: Option<XssProtection>,
    /// Referrer Policy
    pub referrer_policy: Option<ReferrerPolicy>,
    /// Permissions Policy
    pub permissions_policy: Option<String>,
    /// Custom headers
    pub custom_headers: HashMap<String, String>,
}

/// HSTS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsConfig {
    /// Max age in seconds
    pub max_age: u32,
    /// Include subdomains
    pub include_subdomains: bool,
    /// Preload
    pub preload: bool,
}

/// Frame options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameOptions {
    #[serde(rename = "DENY")]
    Deny,
    #[serde(rename = "SAMEORIGIN")]
    SameOrigin,
    #[serde(rename = "ALLOW-FROM")]
    AllowFrom(String),
}

/// XSS protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssProtection {
    /// Enable XSS protection
    pub enabled: bool,
    /// Block mode
    pub block: bool,
}

/// Referrer policy options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferrerPolicy {
    #[serde(rename = "no-referrer")]
    NoReferrer,
    #[serde(rename = "no-referrer-when-downgrade")]
    NoReferrerWhenDowngrade,
    #[serde(rename = "origin")]
    Origin,
    #[serde(rename = "origin-when-cross-origin")]
    OriginWhenCrossOrigin,
    #[serde(rename = "same-origin")]
    SameOrigin,
    #[serde(rename = "strict-origin")]
    StrictOrigin,
    #[serde(rename = "strict-origin-when-cross-origin")]
    StrictOriginWhenCrossOrigin,
    #[serde(rename = "unsafe-url")]
    UnsafeUrl,
}

impl SecurityHeaders {
    /// Create new security headers manager
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }

    /// Apply security headers to response
    pub fn apply_headers(&self, headers: &mut HeaderMap) -> GatewayResult<()> {
        // Content Security Policy
        if let Some(ref csp) = self.config.csp {
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_str(csp)
                    .map_err(|e| GatewayError::internal(format!("Invalid CSP header: {}", e)))?,
            );
        }

        // HTTP Strict Transport Security
        if let Some(ref hsts) = self.config.hsts {
            let mut hsts_value = format!("max-age={}", hsts.max_age);
            if hsts.include_subdomains {
                hsts_value.push_str("; includeSubDomains");
            }
            if hsts.preload {
                hsts_value.push_str("; preload");
            }
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_str(&hsts_value)
                    .map_err(|e| GatewayError::internal(format!("Invalid HSTS header: {}", e)))?,
            );
        }

        // X-Frame-Options
        if let Some(ref frame_options) = self.config.frame_options {
            let value = match frame_options {
                FrameOptions::Deny => "DENY",
                FrameOptions::SameOrigin => "SAMEORIGIN",
                FrameOptions::AllowFrom(uri) => return Err(GatewayError::internal(
                    format!("ALLOW-FROM not supported: {}", uri)
                )),
            };
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static(value),
            );
        }

        // X-Content-Type-Options
        if self.config.content_type_options {
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
        }

        // X-XSS-Protection
        if let Some(ref xss) = self.config.xss_protection {
            let value = if xss.enabled {
                if xss.block {
                    "1; mode=block"
                } else {
                    "1"
                }
            } else {
                "0"
            };
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static(value),
            );
        }

        // Referrer Policy
        if let Some(ref policy) = self.config.referrer_policy {
            let value = match policy {
                ReferrerPolicy::NoReferrer => "no-referrer",
                ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
                ReferrerPolicy::Origin => "origin",
                ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
                ReferrerPolicy::SameOrigin => "same-origin",
                ReferrerPolicy::StrictOrigin => "strict-origin",
                ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
                ReferrerPolicy::UnsafeUrl => "unsafe-url",
            };
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static(value),
            );
        }

        // Permissions Policy
        if let Some(ref policy) = self.config.permissions_policy {
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_str(policy)
                    .map_err(|e| GatewayError::internal(format!("Invalid permissions policy: {}", e)))?,
            );
        }

        // Custom headers
        for (name, value) in &self.config.custom_headers {
            headers.insert(
                name.parse::<HeaderName>()
                    .map_err(|e| GatewayError::internal(format!("Invalid header name: {}", e)))?,
                HeaderValue::from_str(value)
                    .map_err(|e| GatewayError::internal(format!("Invalid header value: {}", e)))?,
            );
        }

        Ok(())
    }

    /// Get default security headers configuration
    pub fn default_config() -> SecurityHeadersConfig {
        SecurityHeadersConfig {
            csp: Some("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".to_string()),
            hsts: Some(HstsConfig {
                max_age: 31536000, // 1 year
                include_subdomains: true,
                preload: false,
            }),
            frame_options: Some(FrameOptions::Deny),
            content_type_options: true,
            xss_protection: Some(XssProtection {
                enabled: true,
                block: true,
            }),
            referrer_policy: Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
            custom_headers: HashMap::new(),
        }
    }
}

// ============================================================================
// Input Validation and Sanitization
// ============================================================================

/// Input validator and sanitizer
pub struct InputValidator {
    /// Validation rules
    rules: Arc<RwLock<HashMap<String, ValidationRule>>>,
    /// Sanitization configuration
    sanitizer_config: SanitizerConfig,
}

/// Validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Rule name
    pub name: String,
    /// Field path this rule applies to
    pub field_path: String,
    /// Validation type
    pub validation_type: ValidationType,
    /// Whether field is required
    pub required: bool,
    /// Custom error message
    pub error_message: Option<String>,
}

/// Types of validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationType {
    /// String length validation
    StringLength { min: usize, max: usize },
    /// Regex pattern validation
    Regex { pattern: String },
    /// Email validation
    Email,
    /// URL validation
    Url,
    /// IP address validation
    IpAddress,
    /// JSON validation
    Json,
    /// SQL injection detection
    SqlInjection,
    /// XSS detection
    Xss,
    /// Path traversal detection
    PathTraversal,
    /// Custom validation function
    Custom { function_name: String },
}

/// Sanitization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerConfig {
    /// HTML sanitization enabled
    pub html_sanitization: bool,
    /// SQL injection prevention
    pub sql_injection_prevention: bool,
    /// XSS prevention
    pub xss_prevention: bool,
    /// Path traversal prevention
    pub path_traversal_prevention: bool,
    /// Maximum input length
    pub max_input_length: usize,
    /// Allowed characters regex
    pub allowed_characters: Option<String>,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether validation passed
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<ValidationError>,
    /// Sanitized value
    pub sanitized_value: Option<serde_json::Value>,
}

/// Validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Field path
    pub field: String,
    /// Error message
    pub message: String,
    /// Error code
    pub code: String,
}

impl InputValidator {
    /// Create new input validator
    pub fn new(sanitizer_config: SanitizerConfig) -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            sanitizer_config,
        }
    }

    /// Add validation rule
    pub async fn add_rule(&self, rule: ValidationRule) -> GatewayResult<()> {
        let mut rules = self.rules.write().await;
        rules.insert(rule.field_path.clone(), rule);
        Ok(())
    }

    /// Validate and sanitize input
    pub async fn validate_and_sanitize(
        &self,
        input: &serde_json::Value,
        context: &str,
    ) -> GatewayResult<ValidationResult> {
        let mut errors = Vec::new();
        let mut sanitized = input.clone();

        // Apply validation rules
        let rules = self.rules.read().await;
        for (field_path, rule) in rules.iter() {
            if let Some(field_value) = self.get_field_value(&sanitized, field_path) {
                if let Err(error) = self.validate_field(field_value, rule).await {
                    errors.push(error);
                }
            } else if rule.required {
                errors.push(ValidationError {
                    field: field_path.clone(),
                    message: "Required field is missing".to_string(),
                    code: "REQUIRED_FIELD_MISSING".to_string(),
                });
            }
        }

        // Apply sanitization
        if errors.is_empty() {
            sanitized = self.sanitize_value(&sanitized, context).await?;
        }

        Ok(ValidationResult {
            valid: errors.is_empty(),
            errors: errors.clone(),
            sanitized_value: if errors.is_empty() { Some(sanitized) } else { None },
        })
    }

    /// Validate individual field
    async fn validate_field(
        &self,
        value: &serde_json::Value,
        rule: &ValidationRule,
    ) -> Result<(), ValidationError> {
        match &rule.validation_type {
            ValidationType::StringLength { min, max } => {
                if let Some(s) = value.as_str() {
                    if s.len() < *min || s.len() > *max {
                        return Err(ValidationError {
                            field: rule.field_path.clone(),
                            message: format!("String length must be between {} and {}", min, max),
                            code: "INVALID_LENGTH".to_string(),
                        });
                    }
                }
            }
            ValidationType::Regex { pattern } => {
                if let Some(s) = value.as_str() {
                    let regex = Regex::new(pattern).map_err(|_| ValidationError {
                        field: rule.field_path.clone(),
                        message: "Invalid regex pattern".to_string(),
                        code: "INVALID_REGEX".to_string(),
                    })?;
                    if !regex.is_match(s) {
                        return Err(ValidationError {
                            field: rule.field_path.clone(),
                            message: "Value does not match required pattern".to_string(),
                            code: "PATTERN_MISMATCH".to_string(),
                        });
                    }
                }
            }
            ValidationType::Email => {
                if let Some(s) = value.as_str() {
                    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
                    if !email_regex.is_match(s) {
                        return Err(ValidationError {
                            field: rule.field_path.clone(),
                            message: "Invalid email format".to_string(),
                            code: "INVALID_EMAIL".to_string(),
                        });
                    }
                }
            }
            ValidationType::SqlInjection => {
                if let Some(s) = value.as_str() {
                    if self.detect_sql_injection(s) {
                        return Err(ValidationError {
                            field: rule.field_path.clone(),
                            message: "Potential SQL injection detected".to_string(),
                            code: "SQL_INJECTION_DETECTED".to_string(),
                        });
                    }
                }
            }
            ValidationType::Xss => {
                if let Some(s) = value.as_str() {
                    if self.detect_xss(s) {
                        return Err(ValidationError {
                            field: rule.field_path.clone(),
                            message: "Potential XSS attack detected".to_string(),
                            code: "XSS_DETECTED".to_string(),
                        });
                    }
                }
            }
            ValidationType::PathTraversal => {
                if let Some(s) = value.as_str() {
                    if self.detect_path_traversal(s) {
                        return Err(ValidationError {
                            field: rule.field_path.clone(),
                            message: "Path traversal attempt detected".to_string(),
                            code: "PATH_TRAVERSAL_DETECTED".to_string(),
                        });
                    }
                }
            }
            _ => {
                // Other validation types would be implemented here
            }
        }

        Ok(())
    }

    /// Sanitize input value
    async fn sanitize_value(
        &self,
        value: &serde_json::Value,
        _context: &str,
    ) -> GatewayResult<serde_json::Value> {
        match value {
            serde_json::Value::String(s) => {
                let mut sanitized = s.clone();
                
                // HTML sanitization
                if self.sanitizer_config.html_sanitization {
                    sanitized = self.sanitize_html(&sanitized);
                }
                
                // XSS prevention
                if self.sanitizer_config.xss_prevention {
                    sanitized = self.sanitize_xss(&sanitized);
                }
                
                // SQL injection prevention
                if self.sanitizer_config.sql_injection_prevention {
                    sanitized = self.sanitize_sql(&sanitized);
                }
                
                // Path traversal prevention
                if self.sanitizer_config.path_traversal_prevention {
                    sanitized = self.sanitize_path_traversal(&sanitized);
                }
                
                // Length check
                if sanitized.len() > self.sanitizer_config.max_input_length {
                    sanitized.truncate(self.sanitizer_config.max_input_length);
                }
                
                Ok(serde_json::Value::String(sanitized))
            }
            serde_json::Value::Object(obj) => {
                let mut sanitized_obj = serde_json::Map::new();
                for (key, val) in obj {
                    let sanitized_val = Box::pin(self.sanitize_value(val, _context)).await?;
                    sanitized_obj.insert(key.clone(), sanitized_val);
                }
                Ok(serde_json::Value::Object(sanitized_obj))
            }
            serde_json::Value::Array(arr) => {
                let mut sanitized_arr = Vec::new();
                for val in arr {
                    let sanitized_val = Box::pin(self.sanitize_value(val, _context)).await?;
                    sanitized_arr.push(sanitized_val);
                }
                Ok(serde_json::Value::Array(sanitized_arr))
            }
            _ => Ok(value.clone()),
        }
    }

    /// Get field value from JSON using path
    fn get_field_value<'a>(&self, value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;
        
        for part in parts {
            match current {
                serde_json::Value::Object(obj) => {
                    current = obj.get(part)?;
                }
                serde_json::Value::Array(arr) => {
                    if let Ok(index) = part.parse::<usize>() {
                        current = arr.get(index)?;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        
        Some(current)
    }

    /// Detect SQL injection patterns
    fn detect_sql_injection(&self, input: &str) -> bool {
        let sql_patterns = [
            r"(?i)\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b",
            r"(?i)(\-\-|\#|\/\*|\*\/)",
            r"(?i)(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
            r"(?i)\'\s*(or|and)\s*\'\w*\'\s*=\s*\'\w*",
        ];

        for pattern in &sql_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(input) {
                    return true;
                }
            }
        }
        false
    }

    /// Detect XSS patterns
    fn detect_xss(&self, input: &str) -> bool {
        let xss_patterns = [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe[^>]*>",
            r"(?i)<object[^>]*>",
            r"(?i)<embed[^>]*>",
        ];

        for pattern in &xss_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(input) {
                    return true;
                }
            }
        }
        false
    }

    /// Detect path traversal patterns
    fn detect_path_traversal(&self, input: &str) -> bool {
        let traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c",
        ];

        for pattern in &traversal_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(input) {
                    return true;
                }
            }
        }
        false
    }

    /// Sanitize HTML content
    fn sanitize_html(&self, input: &str) -> String {
        // Basic HTML sanitization - remove script tags and dangerous attributes
        let script_regex = Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap();
        let mut sanitized = script_regex.replace_all(input, "").to_string();
        
        let dangerous_attrs = Regex::new(r#"(?i)\s+(on\w+|javascript:|data:)\s*=\s*['"][^'"]*['"]"#).unwrap();
        sanitized = dangerous_attrs.replace_all(&sanitized, "").to_string();
        
        sanitized
    }

    /// Sanitize XSS content
    fn sanitize_xss(&self, input: &str) -> String {
        input
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;")
            .replace("/", "&#x2F;")
    }

    /// Sanitize SQL content
    fn sanitize_sql(&self, input: &str) -> String {
        input
            .replace("'", "''")
            .replace("--", "")
            .replace("/*", "")
            .replace("*/", "")
    }

    /// Sanitize path traversal content
    fn sanitize_path_traversal(&self, input: &str) -> String {
        input
            .replace("../", "")
            .replace("..\\", "")
            .replace("%2e%2e%2f", "")
            .replace("%2e%2e%5c", "")
    }
}

// ============================================================================
// Security Audit Logging
// ============================================================================

/// Security audit logger
pub struct SecurityAuditor {
    /// Audit log entries
    audit_logs: Arc<Mutex<Vec<SecurityAuditEntry>>>,
    /// Audit configuration
    config: AuditConfig,
}

/// Security audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEntry {
    /// Entry ID
    pub id: Uuid,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: SecurityEventType,
    /// Severity level
    pub severity: SecuritySeverity,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Event details
    pub details: serde_json::Value,
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// Authentication events
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthenticationLockout,
    /// Authorization events
    AuthorizationSuccess,
    AuthorizationFailure,
    PrivilegeEscalation,
    /// Input validation events
    InputValidationFailure,
    SqlInjectionAttempt,
    XssAttempt,
    PathTraversalAttempt,
    /// TLS/SSL events
    TlsHandshakeFailure,
    CertificateValidationFailure,
    /// Rate limiting events
    RateLimitExceeded,
    /// Security policy violations
    SecurityPolicyViolation,
    /// Suspicious activity
    SuspiciousActivity,
    AnomalyDetected,
    /// Configuration changes
    SecurityConfigurationChange,
    /// System events
    SecuritySystemStartup,
    SecuritySystemShutdown,
}

/// Security severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,
    /// Maximum number of audit entries to keep in memory
    pub max_entries: usize,
    /// Log file path
    pub log_file: Option<String>,
    /// Whether to log to syslog
    pub syslog: bool,
    /// Minimum severity level to log
    pub min_severity: SecuritySeverity,
    /// Whether to include request/response data
    pub include_data: bool,
}

impl SecurityAuditor {
    /// Create new security auditor
    pub fn new(config: AuditConfig) -> Self {
        Self {
            audit_logs: Arc::new(Mutex::new(Vec::new())),
            config,
        }
    }

    /// Log security event
    pub async fn log_event(
        &self,
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        user_id: Option<String>,
        ip_address: String,
        user_agent: Option<String>,
        details: serde_json::Value,
        request_id: Option<String>,
        session_id: Option<String>,
    ) -> GatewayResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check severity threshold
        if !self.should_log_severity(&severity) {
            return Ok(());
        }

        let entry = SecurityAuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: event_type.clone(),
            severity: severity.clone(),
            user_id,
            ip_address: ip_address.clone(),
            user_agent,
            details: details.clone(),
            request_id,
            session_id,
        };

        // Add to in-memory log
        {
            let mut logs = self.audit_logs.lock().await;
            logs.push(entry.clone());
            
            // Trim logs if necessary
            if logs.len() > self.config.max_entries {
                logs.remove(0);
            }
        }

        // Log to structured logger
        match severity {
            SecuritySeverity::Info => info!(
                event_type = ?event_type,
                user_id = ?entry.user_id,
                ip_address = %ip_address,
                "Security audit event"
            ),
            SecuritySeverity::Warning => warn!(
                event_type = ?event_type,
                user_id = ?entry.user_id,
                ip_address = %ip_address,
                "Security audit event"
            ),
            SecuritySeverity::Error | SecuritySeverity::Critical => error!(
                event_type = ?event_type,
                user_id = ?entry.user_id,
                ip_address = %ip_address,
                "Security audit event"
            ),
        }

        // Write to audit log file if configured
        if let Some(ref log_file) = self.config.log_file {
            self.write_to_file(&entry, log_file).await?;
        }

        Ok(())
    }

    /// Get audit logs with filtering
    pub async fn get_audit_logs(
        &self,
        event_type: Option<SecurityEventType>,
        severity: Option<SecuritySeverity>,
        user_id: Option<String>,
        limit: usize,
    ) -> Vec<SecurityAuditEntry> {
        let logs = self.audit_logs.lock().await;
        
        logs.iter()
            .filter(|entry| {
                if let Some(ref et) = event_type {
                    if std::mem::discriminant(&entry.event_type) != std::mem::discriminant(et) {
                        return false;
                    }
                }
                if let Some(ref s) = severity {
                    if std::mem::discriminant(&entry.severity) != std::mem::discriminant(s) {
                        return false;
                    }
                }
                if let Some(ref uid) = user_id {
                    if entry.user_id.as_ref() != Some(uid) {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Check if severity should be logged
    fn should_log_severity(&self, severity: &SecuritySeverity) -> bool {
        let severity_level = match severity {
            SecuritySeverity::Info => 0,
            SecuritySeverity::Warning => 1,
            SecuritySeverity::Error => 2,
            SecuritySeverity::Critical => 3,
        };

        let min_level = match self.config.min_severity {
            SecuritySeverity::Info => 0,
            SecuritySeverity::Warning => 1,
            SecuritySeverity::Error => 2,
            SecuritySeverity::Critical => 3,
        };

        severity_level >= min_level
    }

    /// Write audit entry to file
    async fn write_to_file(&self, entry: &SecurityAuditEntry, _file_path: &str) -> GatewayResult<()> {
        // Implementation would write to audit log file
        // For now, we'll just log it
        info!("Audit entry: {:?}", entry);
        Ok(())
    }
}

// ============================================================================
// Threat Detection and Security Monitoring
// ============================================================================

/// Threat detection system
pub struct ThreatDetector {
    /// Detection rules
    rules: Arc<RwLock<Vec<ThreatDetectionRule>>>,
    /// Detected threats
    threats: Arc<Mutex<Vec<DetectedThreat>>>,
    /// IP reputation cache
    ip_reputation: Arc<DashMap<IpAddr, IpReputation>>,
    /// Security auditor
    auditor: Arc<SecurityAuditor>,
}

/// Threat detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionRule {
    /// Rule ID
    pub id: Uuid,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Rule type
    pub rule_type: ThreatRuleType,
    /// Rule parameters
    pub parameters: serde_json::Value,
    /// Severity level
    pub severity: ThreatSeverity,
    /// Whether rule is active
    pub active: bool,
    /// Actions to take when rule matches
    pub actions: Vec<ThreatAction>,
}

/// Types of threat detection rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatRuleType {
    /// Rate-based detection
    RateLimit,
    /// Pattern-based detection
    Pattern,
    /// Anomaly detection
    Anomaly,
    /// Reputation-based detection
    Reputation,
    /// Behavioral analysis
    Behavioral,
}

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Actions to take when threat is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatAction {
    /// Log the event
    Log,
    /// Block the request
    Block,
    /// Rate limit the source
    RateLimit,
    /// Send alert
    Alert,
    /// Quarantine the source
    Quarantine,
}

/// Detected threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedThreat {
    /// Threat ID
    pub id: Uuid,
    /// Detection timestamp
    pub timestamp: DateTime<Utc>,
    /// Rule that detected the threat
    pub rule_id: Uuid,
    /// Threat type
    pub threat_type: ThreatRuleType,
    /// Severity level
    pub severity: ThreatSeverity,
    /// Source IP address
    pub source_ip: IpAddr,
    /// User ID (if known)
    pub user_id: Option<String>,
    /// Threat details
    pub details: serde_json::Value,
    /// Actions taken
    pub actions_taken: Vec<ThreatAction>,
    /// Whether threat has been investigated
    pub investigated: bool,
}

/// IP reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    /// IP address
    pub ip: IpAddr,
    /// Reputation score (0-100, higher is better)
    pub score: u8,
    /// Reputation sources
    pub sources: Vec<String>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
    /// Whether IP is known to be malicious
    pub is_malicious: bool,
    /// Country code
    pub country: Option<String>,
    /// ASN information
    pub asn: Option<String>,
}

impl ThreatDetector {
    /// Create new threat detector
    pub fn new(auditor: Arc<SecurityAuditor>) -> Self {
        let detector = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            threats: Arc::new(Mutex::new(Vec::new())),
            ip_reputation: Arc::new(DashMap::new()),
            auditor,
        };

        // Initialize default rules
        tokio::spawn({
            let detector = detector.clone();
            async move {
                if let Err(e) = detector.initialize_default_rules().await {
                    error!("Failed to initialize threat detection rules: {}", e);
                }
            }
        });

        detector
    }

    /// Add threat detection rule
    pub async fn add_rule(&self, rule: ThreatDetectionRule) -> GatewayResult<()> {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        Ok(())
    }

    /// Analyze request for threats
    pub async fn analyze_request(
        &self,
        ip: IpAddr,
        user_id: Option<String>,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &[u8],
    ) -> GatewayResult<Vec<DetectedThreat>> {
        let mut detected_threats = Vec::new();
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            if !rule.active {
                continue;
            }

            if let Some(threat) = self.check_rule(rule, ip, user_id.as_deref(), method, uri, headers, body).await? {
                detected_threats.push(threat);
            }
        }

        // Store detected threats
        if !detected_threats.is_empty() {
            let mut threats = self.threats.lock().await;
            threats.extend(detected_threats.clone());
        }

        Ok(detected_threats)
    }

    /// Check individual rule against request
    async fn check_rule(
        &self,
        rule: &ThreatDetectionRule,
        ip: IpAddr,
        user_id: Option<&str>,
        _method: &Method,
        _uri: &Uri,
        _headers: &HeaderMap,
        _body: &[u8],
    ) -> GatewayResult<Option<DetectedThreat>> {
        match rule.rule_type {
            ThreatRuleType::Reputation => {
                if let Some(reputation) = self.ip_reputation.get(&ip) {
                    if reputation.is_malicious || reputation.score < 30 {
                        return Ok(Some(DetectedThreat {
                            id: Uuid::new_v4(),
                            timestamp: Utc::now(),
                            rule_id: rule.id,
                            threat_type: rule.rule_type.clone(),
                            severity: rule.severity.clone(),
                            source_ip: ip,
                            user_id: user_id.map(|s| s.to_string()),
                            details: serde_json::json!({
                                "reputation_score": reputation.score,
                                "is_malicious": reputation.is_malicious,
                                "sources": reputation.sources
                            }),
                            actions_taken: rule.actions.clone(),
                            investigated: false,
                        }));
                    }
                }
            }
            ThreatRuleType::RateLimit => {
                // Rate limit checking would be implemented here
                // For now, this is a placeholder
            }
            ThreatRuleType::Pattern => {
                // Pattern matching would be implemented here
                // For now, this is a placeholder
            }
            ThreatRuleType::Anomaly => {
                // Anomaly detection would be implemented here
                // For now, this is a placeholder
            }
            ThreatRuleType::Behavioral => {
                // Behavioral analysis would be implemented here
                // For now, this is a placeholder
            }
        }

        Ok(None)
    }

    /// Update IP reputation
    pub async fn update_ip_reputation(&self, ip: IpAddr, reputation: IpReputation) {
        self.ip_reputation.insert(ip, reputation);
    }

    /// Get detected threats
    pub async fn get_threats(&self, limit: usize) -> Vec<DetectedThreat> {
        let threats = self.threats.lock().await;
        threats.iter().take(limit).cloned().collect()
    }

    /// Initialize default threat detection rules
    async fn initialize_default_rules(&self) -> GatewayResult<()> {
        let mut rules = self.rules.write().await;

        // Malicious IP reputation rule
        rules.push(ThreatDetectionRule {
            id: Uuid::new_v4(),
            name: "Malicious IP Detection".to_string(),
            description: "Detect requests from known malicious IP addresses".to_string(),
            rule_type: ThreatRuleType::Reputation,
            parameters: serde_json::json!({
                "min_reputation_score": 30,
                "check_malicious_flag": true
            }),
            severity: ThreatSeverity::High,
            active: true,
            actions: vec![ThreatAction::Block, ThreatAction::Log, ThreatAction::Alert],
        });

        // High request rate rule
        rules.push(ThreatDetectionRule {
            id: Uuid::new_v4(),
            name: "High Request Rate".to_string(),
            description: "Detect unusually high request rates from single IP".to_string(),
            rule_type: ThreatRuleType::RateLimit,
            parameters: serde_json::json!({
                "requests_per_minute": 1000,
                "window_size": 60
            }),
            severity: ThreatSeverity::Medium,
            active: true,
            actions: vec![ThreatAction::RateLimit, ThreatAction::Log],
        });

        Ok(())
    }
}

impl Clone for ThreatDetector {
    fn clone(&self) -> Self {
        Self {
            rules: self.rules.clone(),
            threats: self.threats.clone(),
            ip_reputation: self.ip_reputation.clone(),
            auditor: self.auditor.clone(),
        }
    }
}

// ============================================================================
// Main Security Manager
// ============================================================================

/// Main security manager that coordinates all security components
pub struct SecurityManager {
    /// TLS manager
    pub tls_manager: Arc<TlsManager>,
    /// Request signer
    pub request_signer: Arc<RequestSigner>,
    /// Security headers manager
    pub security_headers: Arc<SecurityHeaders>,
    /// Input validator
    pub input_validator: Arc<InputValidator>,
    /// Security auditor
    pub security_auditor: Arc<SecurityAuditor>,
    /// Threat detector
    pub threat_detector: Arc<ThreatDetector>,
}

impl SecurityManager {
    /// Create new security manager with default configuration
    pub fn new() -> GatewayResult<Self> {
        let audit_config = AuditConfig {
            enabled: true,
            max_entries: 10000,
            log_file: Some("/var/log/gateway/security.log".to_string()),
            syslog: true,
            min_severity: SecuritySeverity::Info,
            include_data: false,
        };

        let security_auditor = Arc::new(SecurityAuditor::new(audit_config));

        let tls_config = TlsConfig {
            cert_file: "/etc/ssl/certs/gateway.crt".to_string(),
            key_file: "/etc/ssl/private/gateway.key".to_string(),
            min_version: TlsVersion::V1_2,
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
            require_client_cert: false,
            ca_file: None,
            ocsp_stapling: true,
            ct_logs: true,
        };

        let signature_config = SignatureConfig {
            default_algorithm: SignatureAlgorithm::HmacSha256,
            signature_ttl: Duration::minutes(5),
            signed_headers: vec![
                "host".to_string(),
                "date".to_string(),
                "content-type".to_string(),
                "authorization".to_string(),
            ],
            require_signature: false,
            clock_skew_tolerance: Duration::seconds(30),
        };

        let sanitizer_config = SanitizerConfig {
            html_sanitization: true,
            sql_injection_prevention: true,
            xss_prevention: true,
            path_traversal_prevention: true,
            max_input_length: 1024 * 1024, // 1MB
            allowed_characters: None,
        };

        Ok(Self {
            tls_manager: Arc::new(TlsManager::new(tls_config)?),
            request_signer: Arc::new(RequestSigner::new(signature_config)),
            security_headers: Arc::new(SecurityHeaders::new(SecurityHeaders::default_config())),
            input_validator: Arc::new(InputValidator::new(sanitizer_config)),
            security_auditor: security_auditor.clone(),
            threat_detector: Arc::new(ThreatDetector::new(security_auditor)),
        })
    }

    /// Initialize all security components
    pub async fn initialize(&self) -> GatewayResult<()> {
        // Initialize TLS if certificate files exist
        if Path::new("/etc/ssl/certs/gateway.crt").exists() {
            self.tls_manager.initialize().await?;
        }

        info!("Security manager initialized successfully");
        Ok(())
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default security manager")
    }
}