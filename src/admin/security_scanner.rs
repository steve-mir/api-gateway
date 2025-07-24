//! # Admin API Security Scanner and Vulnerability Assessment
//!
//! This module provides automated security scanning and vulnerability assessment
//! for admin APIs. It includes:
//! - Automated security scans of admin endpoints
//! - Vulnerability detection and classification
//! - Security policy compliance checking
//! - Penetration testing capabilities
//! - Security report generation

use crate::core::error::{GatewayError, GatewayResult};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

// ============================================================================
// HTTP Method Serialization Helper
// ============================================================================

mod http_method_serde {
    use axum::http::Method;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(method: &Method, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        method.as_str().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Method, D::Error>
    where
        D: Deserializer<'de>,
    {
        let method_str = String::deserialize(deserializer)?;
        method_str.parse().map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Security Scanner Core
// ============================================================================

/// Security scanner for admin APIs
pub struct SecurityScanner {
    /// HTTP client for making requests
    client: Client,
    /// Scan configurations
    scan_configs: Arc<RwLock<HashMap<String, ScanConfig>>>,
    /// Scan results
    scan_results: Arc<DashMap<Uuid, ScanResult>>,
    /// Vulnerability database
    vulnerability_db: Arc<RwLock<VulnerabilityDatabase>>,
    /// Active scans
    active_scans: Arc<Mutex<HashMap<Uuid, ScanProgress>>>,
}

/// Security scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Scan name
    pub name: String,
    /// Target endpoints to scan
    pub targets: Vec<ScanTarget>,
    /// Scan types to perform
    pub scan_types: Vec<ScanType>,
    /// Scan schedule (cron expression)
    pub schedule: Option<String>,
    /// Maximum scan duration
    pub max_duration: Duration,
    /// Whether scan is enabled
    pub enabled: bool,
    /// Notification settings
    pub notifications: NotificationConfig,
}

/// Scan target specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Base URL
    pub base_url: String,
    /// Endpoints to scan
    pub endpoints: Vec<String>,
    /// Authentication method
    pub auth: AuthMethod,
    /// Custom headers
    pub headers: HashMap<String, String>,
}

/// Authentication method for scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    None,
    Bearer { token: String },
    ApiKey { key: String },
    Basic { username: String, password: String },
}

/// Types of security scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    /// OWASP Top 10 vulnerabilities
    OwaspTop10,
    /// Authentication and authorization flaws
    AuthenticationFlaws,
    /// Input validation vulnerabilities
    InputValidation,
    /// Configuration security issues
    ConfigurationSecurity,
    /// API-specific vulnerabilities
    ApiSecurity,
    /// Rate limiting bypass attempts
    RateLimitingBypass,
    /// Session management flaws
    SessionManagement,
    /// Information disclosure
    InformationDisclosure,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Email notifications
    pub email: Option<EmailConfig>,
    /// Webhook notifications
    pub webhook: Option<WebhookConfig>,
    /// Severity threshold for notifications
    pub severity_threshold: VulnerabilitySeverity,
}

/// Email notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub recipients: Vec<String>,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
}

/// Webhook notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub retry_count: u32,
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Scan ID
    pub scan_id: Uuid,
    /// Scan configuration used
    pub config_name: String,
    /// Scan start time
    pub started_at: DateTime<Utc>,
    /// Scan completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Scan status
    pub status: ScanStatus,
    /// Discovered vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    /// Scan statistics
    pub statistics: ScanStatistics,
    /// Error message if scan failed
    pub error_message: Option<String>,
}

/// Scan status
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Scan ID
    pub scan_id: Uuid,
    /// Current phase
    pub current_phase: String,
    /// Progress percentage (0-100)
    pub progress_percent: u8,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Vulnerabilities found so far
    pub vulnerabilities_found: u32,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Total endpoints scanned
    pub endpoints_scanned: u32,
    /// Total requests made
    pub requests_made: u32,
    /// Scan duration
    pub duration: Duration,
    /// Vulnerabilities by severity
    pub vulnerabilities_by_severity: HashMap<VulnerabilitySeverity, u32>,
    /// False positive rate
    pub false_positive_rate: f64,
}

/// Discovered vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Vulnerability ID
    pub id: Uuid,
    /// Vulnerability type
    pub vulnerability_type: VulnerabilityType,
    /// Severity level
    pub severity: VulnerabilitySeverity,
    /// Affected endpoint
    pub endpoint: String,
    /// HTTP method
    #[serde(with = "http_method_serde")]
    pub method: Method,
    /// Vulnerability description
    pub description: String,
    /// Proof of concept
    pub proof_of_concept: Option<String>,
    /// Remediation advice
    pub remediation: String,
    /// CWE ID if applicable
    pub cwe_id: Option<u32>,
    /// CVE ID if applicable
    pub cve_id: Option<String>,
    /// CVSS score
    pub cvss_score: Option<f64>,
    /// Discovery timestamp
    pub discovered_at: DateTime<Utc>,
    /// Whether this is a false positive
    pub false_positive: bool,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityType {
    /// SQL Injection
    SqlInjection,
    /// Cross-Site Scripting (XSS)
    CrossSiteScripting,
    /// Cross-Site Request Forgery (CSRF)
    CrossSiteRequestForgery,
    /// Authentication bypass
    AuthenticationBypass,
    /// Authorization bypass
    AuthorizationBypass,
    /// Information disclosure
    InformationDisclosure,
    /// Insecure direct object reference
    InsecureDirectObjectReference,
    /// Security misconfiguration
    SecurityMisconfiguration,
    /// Sensitive data exposure
    SensitiveDataExposure,
    /// Insufficient logging and monitoring
    InsufficientLogging,
    /// Rate limiting bypass
    RateLimitingBypass,
    /// Session fixation
    SessionFixation,
    /// Weak cryptography
    WeakCryptography,
    /// API abuse
    ApiAbuse,
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Vulnerability database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDatabase {
    /// Known vulnerability patterns
    pub patterns: Vec<VulnerabilityPattern>,
    /// Signature database
    pub signatures: Vec<VulnerabilitySignature>,
    /// Last update timestamp
    pub last_updated: DateTime<Utc>,
}

/// Vulnerability detection pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    /// Pattern ID
    pub id: Uuid,
    /// Pattern name
    pub name: String,
    /// Vulnerability type this pattern detects
    pub vulnerability_type: VulnerabilityType,
    /// HTTP method pattern
    pub method_pattern: Option<String>,
    /// URL path pattern
    pub path_pattern: Option<String>,
    /// Request header patterns
    pub header_patterns: HashMap<String, String>,
    /// Request body pattern
    pub body_pattern: Option<String>,
    /// Response patterns that indicate vulnerability
    pub response_patterns: Vec<ResponsePattern>,
    /// Severity of vulnerabilities detected by this pattern
    pub severity: VulnerabilitySeverity,
}

/// Response pattern for vulnerability detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePattern {
    /// Status code pattern
    pub status_code: Option<u16>,
    /// Response header patterns
    pub header_patterns: HashMap<String, String>,
    /// Response body pattern
    pub body_pattern: Option<String>,
    /// Response time threshold
    pub response_time_threshold: Option<Duration>,
}

/// Vulnerability signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySignature {
    /// Signature ID
    pub id: Uuid,
    /// Signature name
    pub name: String,
    /// Regular expression pattern
    pub regex_pattern: String,
    /// Vulnerability type
    pub vulnerability_type: VulnerabilityType,
    /// Severity
    pub severity: VulnerabilitySeverity,
    /// Description
    pub description: String,
}

impl SecurityScanner {
    pub fn new() -> Self {
        let scanner = Self {
            client: Client::new(),
            scan_configs: Arc::new(RwLock::new(HashMap::new())),
            scan_results: Arc::new(DashMap::new()),
            vulnerability_db: Arc::new(RwLock::new(VulnerabilityDatabase {
                patterns: Vec::new(),
                signatures: Vec::new(),
                last_updated: Utc::now(),
            })),
            active_scans: Arc::new(Mutex::new(HashMap::new())),
        };

        // Initialize default vulnerability patterns
        tokio::spawn({
            let scanner = scanner.clone();
            async move {
                if let Err(e) = scanner.initialize_vulnerability_database().await {
                    tracing::error!("Failed to initialize vulnerability database: {}", e);
                }
            }
        });

        scanner
    }

    /// Start a security scan
    pub async fn start_scan(&self, config_name: &str) -> GatewayResult<Uuid> {
        let scan_configs = self.scan_configs.read().await;
        let config = scan_configs.get(config_name)
            .ok_or_else(|| GatewayError::not_found("Scan configuration not found"))?
            .clone();

        if !config.enabled {
            return Err(GatewayError::invalid_input("Scan configuration is disabled"));
        }

        let scan_id = Uuid::new_v4();
        let scan_result = ScanResult {
            scan_id,
            config_name: config_name.to_string(),
            started_at: Utc::now(),
            completed_at: None,
            status: ScanStatus::Running,
            vulnerabilities: Vec::new(),
            statistics: ScanStatistics {
                endpoints_scanned: 0,
                requests_made: 0,
                duration: Duration::zero(),
                vulnerabilities_by_severity: HashMap::new(),
                false_positive_rate: 0.0,
            },
            error_message: None,
        };

        self.scan_results.insert(scan_id, scan_result);

        // Start scan in background
        let scanner = self.clone();
        tokio::spawn(async move {
            if let Err(e) = scanner.execute_scan(scan_id, config).await {
                tracing::error!(scan_id = %scan_id, error = %e, "Scan failed");
                if let Some(mut result) = scanner.scan_results.get_mut(&scan_id) {
                    result.status = ScanStatus::Failed;
                    result.error_message = Some(e.to_string());
                    result.completed_at = Some(Utc::now());
                }
            }
        });

        tracing::info!(scan_id = %scan_id, config = %config_name, "Security scan started");
        Ok(scan_id)
    }

    /// Execute a security scan
    async fn execute_scan(&self, scan_id: Uuid, config: ScanConfig) -> GatewayResult<()> {
        let start_time = Utc::now();
        let mut vulnerabilities = Vec::new();
        let mut endpoints_scanned = 0;
        let mut requests_made = 0;

        // Update progress
        {
            let mut active_scans = self.active_scans.lock().await;
            active_scans.insert(scan_id, ScanProgress {
                scan_id,
                current_phase: "Initializing".to_string(),
                progress_percent: 0,
                eta: Some(config.max_duration),
                vulnerabilities_found: 0,
            });
        }

        for target in &config.targets {
            for endpoint in &target.endpoints {
                endpoints_scanned += 1;
                
                // Update progress
                {
                    let mut active_scans = self.active_scans.lock().await;
                    if let Some(progress) = active_scans.get_mut(&scan_id) {
                        progress.current_phase = format!("Scanning {}", endpoint);
                        progress.progress_percent = ((endpoints_scanned as f64 / (config.targets.len() * target.endpoints.len()) as f64) * 100.0) as u8;
                    }
                }

                for scan_type in &config.scan_types {
                    let scan_vulnerabilities = self.scan_endpoint(target, endpoint, scan_type).await?;
                    vulnerabilities.extend(scan_vulnerabilities);
                    requests_made += 1;

                    // Check timeout
                    if Utc::now() - start_time > config.max_duration {
                        tracing::warn!(scan_id = %scan_id, "Scan timeout reached");
                        break;
                    }
                }
            }
        }

        // Calculate statistics
        let duration = Utc::now() - start_time;
        let mut vulnerabilities_by_severity = HashMap::new();
        for vuln in &vulnerabilities {
            *vulnerabilities_by_severity.entry(vuln.severity).or_insert(0) += 1;
        }

        // Update scan result
        if let Some(mut result) = self.scan_results.get_mut(&scan_id) {
            result.status = ScanStatus::Completed;
            result.completed_at = Some(Utc::now());
            result.vulnerabilities = vulnerabilities.clone();
            result.statistics = ScanStatistics {
                endpoints_scanned,
                requests_made,
                duration,
                vulnerabilities_by_severity,
                false_positive_rate: 0.0, // Would be calculated based on historical data
            };
        }

        // Remove from active scans
        {
            let mut active_scans = self.active_scans.lock().await;
            active_scans.remove(&scan_id);
        }

        // Send notifications if configured
        let threshold = config.notifications.severity_threshold;
        if vulnerabilities.iter().any(|v| v.severity as u8 >= threshold as u8) {
            self.send_notifications(&config.notifications, &vulnerabilities).await?;
        }

        tracing::info!(
            scan_id = %scan_id,
            vulnerabilities_found = vulnerabilities.len(),
            duration_seconds = duration.num_seconds(),
            "Security scan completed"
        );

        Ok(())
    }

    /// Scan a specific endpoint for vulnerabilities
    async fn scan_endpoint(
        &self,
        target: &ScanTarget,
        endpoint: &str,
        scan_type: &ScanType,
    ) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let url = format!("{}{}", target.base_url, endpoint);

        match scan_type {
            ScanType::OwaspTop10 => {
                vulnerabilities.extend(self.scan_owasp_top10(&url, target).await?);
            }
            ScanType::AuthenticationFlaws => {
                vulnerabilities.extend(self.scan_authentication_flaws(&url, target).await?);
            }
            ScanType::InputValidation => {
                vulnerabilities.extend(self.scan_input_validation(&url, target).await?);
            }
            ScanType::ConfigurationSecurity => {
                vulnerabilities.extend(self.scan_configuration_security(&url, target).await?);
            }
            ScanType::ApiSecurity => {
                vulnerabilities.extend(self.scan_api_security(&url, target).await?);
            }
            ScanType::RateLimitingBypass => {
                vulnerabilities.extend(self.scan_rate_limiting_bypass(&url, target).await?);
            }
            ScanType::SessionManagement => {
                vulnerabilities.extend(self.scan_session_management(&url, target).await?);
            }
            ScanType::InformationDisclosure => {
                vulnerabilities.extend(self.scan_information_disclosure(&url, target).await?);
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for OWASP Top 10 vulnerabilities
    async fn scan_owasp_top10(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for SQL injection
        let sql_payloads = vec![
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL, NULL, NULL--",
        ];

        for payload in sql_payloads {
            let test_url = format!("{}?id={}", url, payload);
            if let Ok(response) = self.make_request(&test_url, Method::GET, target).await {
                if self.detect_sql_injection_response(&response).await {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::SqlInjection,
                        severity: VulnerabilitySeverity::High,
                        endpoint: url.to_string(),
                        method: Method::GET,
                        description: "Potential SQL injection vulnerability detected".to_string(),
                        proof_of_concept: Some(format!("Payload: {}", payload)),
                        remediation: "Use parameterized queries and input validation".to_string(),
                        cwe_id: Some(89),
                        cve_id: None,
                        cvss_score: Some(8.1),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                    break;
                }
            }
        }

        // Test for XSS
        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
        ];

        for payload in xss_payloads {
            let test_url = format!("{}?search={}", url, payload);
            if let Ok(response) = self.make_request(&test_url, Method::GET, target).await {
                if response.contains(payload) {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::CrossSiteScripting,
                        severity: VulnerabilitySeverity::Medium,
                        endpoint: url.to_string(),
                        method: Method::GET,
                        description: "Potential XSS vulnerability detected".to_string(),
                        proof_of_concept: Some(format!("Payload: {}", payload)),
                        remediation: "Implement proper input validation and output encoding".to_string(),
                        cwe_id: Some(79),
                        cve_id: None,
                        cvss_score: Some(6.1),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                    break;
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for authentication flaws
    async fn scan_authentication_flaws(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for authentication bypass
        let bypass_headers = vec![
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
        ];

        for (header_name, header_value) in bypass_headers {
            let mut headers = HeaderMap::new();
            headers.insert(header_name, header_value.parse().unwrap());
            
            if let Ok(response) = self.make_request_with_headers(url, Method::GET, target, headers).await {
                if response.contains("admin") || response.contains("dashboard") {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::AuthenticationBypass,
                        severity: VulnerabilitySeverity::High,
                        endpoint: url.to_string(),
                        method: Method::GET,
                        description: "Potential authentication bypass via header manipulation".to_string(),
                        proof_of_concept: Some(format!("Header: {}: {}", header_name, header_value)),
                        remediation: "Implement proper authentication validation".to_string(),
                        cwe_id: Some(287),
                        cve_id: None,
                        cvss_score: Some(7.5),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for input validation vulnerabilities
    async fn scan_input_validation(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for path traversal
        let path_traversal_payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ];

        for payload in path_traversal_payloads {
            let test_url = format!("{}?file={}", url, payload);
            if let Ok(response) = self.make_request(&test_url, Method::GET, target).await {
                if response.contains("root:") || response.contains("localhost") {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::InsecureDirectObjectReference,
                        severity: VulnerabilitySeverity::High,
                        endpoint: url.to_string(),
                        method: Method::GET,
                        description: "Path traversal vulnerability detected".to_string(),
                        proof_of_concept: Some(format!("Payload: {}", payload)),
                        remediation: "Implement proper input validation and file access controls".to_string(),
                        cwe_id: Some(22),
                        cve_id: None,
                        cvss_score: Some(7.5),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                    break;
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for configuration security issues
    async fn scan_configuration_security(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for debug endpoints
        let debug_endpoints = vec![
            "/debug",
            "/admin",
            "/.env",
            "/config",
            "/status",
            "/health",
        ];

        for endpoint in debug_endpoints {
            let test_url = format!("{}{}", url, endpoint);
            if let Ok(response) = self.make_request(&test_url, Method::GET, target).await {
                if response.contains("debug") || response.contains("config") || response.contains("password") {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::InformationDisclosure,
                        severity: VulnerabilitySeverity::Medium,
                        endpoint: test_url,
                        method: Method::GET,
                        description: "Information disclosure via debug endpoint".to_string(),
                        proof_of_concept: Some(format!("Endpoint: {}", endpoint)),
                        remediation: "Disable debug endpoints in production".to_string(),
                        cwe_id: Some(200),
                        cve_id: None,
                        cvss_score: Some(5.3),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for API security issues
    async fn scan_api_security(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for API versioning issues
        let version_tests = vec![
            "/v1/",
            "/v2/",
            "/api/v1/",
            "/api/v2/",
        ];

        for version in version_tests {
            let test_url = format!("{}{}", url, version);
            if let Ok(response) = self.make_request(&test_url, Method::GET, target).await {
                if response.contains("deprecated") || response.contains("legacy") {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::SecurityMisconfiguration,
                        severity: VulnerabilitySeverity::Low,
                        endpoint: test_url,
                        method: Method::GET,
                        description: "Deprecated API version accessible".to_string(),
                        proof_of_concept: Some(format!("Version: {}", version)),
                        remediation: "Remove or properly secure deprecated API versions".to_string(),
                        cwe_id: Some(16),
                        cve_id: None,
                        cvss_score: Some(3.7),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for rate limiting bypass
    async fn scan_rate_limiting_bypass(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test rate limiting with different headers
        let bypass_headers = vec![
            ("X-Forwarded-For", "192.168.1.1"),
            ("X-Real-IP", "10.0.0.1"),
            ("X-Client-IP", "172.16.0.1"),
        ];

        for (header_name, header_value) in bypass_headers {
            let mut success_count = 0;
            
            for _ in 0..10 {
                let mut headers = HeaderMap::new();
                headers.insert(header_name, header_value.parse().unwrap());
                
                if let Ok(_) = self.make_request_with_headers(url, Method::GET, target, headers).await {
                    success_count += 1;
                }
            }

            if success_count >= 8 { // If most requests succeeded, rate limiting might be bypassed
                vulnerabilities.push(Vulnerability {
                    id: Uuid::new_v4(),
                    vulnerability_type: VulnerabilityType::RateLimitingBypass,
                    severity: VulnerabilitySeverity::Medium,
                    endpoint: url.to_string(),
                    method: Method::GET,
                    description: "Rate limiting bypass possible via header manipulation".to_string(),
                    proof_of_concept: Some(format!("Header: {}: {}", header_name, header_value)),
                    remediation: "Implement proper rate limiting that cannot be bypassed via headers".to_string(),
                    cwe_id: Some(770),
                    cve_id: None,
                    cvss_score: Some(5.3),
                    discovered_at: Utc::now(),
                    false_positive: false,
                    metadata: HashMap::new(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for session management flaws
    async fn scan_session_management(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for session fixation
        if let Ok(response) = self.make_request(url, Method::GET, target).await {
            if response.contains("JSESSIONID") || response.contains("PHPSESSID") {
                vulnerabilities.push(Vulnerability {
                    id: Uuid::new_v4(),
                    vulnerability_type: VulnerabilityType::SessionFixation,
                    severity: VulnerabilitySeverity::Medium,
                    endpoint: url.to_string(),
                    method: Method::GET,
                    description: "Potential session management vulnerability".to_string(),
                    proof_of_concept: Some("Session ID found in response".to_string()),
                    remediation: "Implement secure session management practices".to_string(),
                    cwe_id: Some(384),
                    cve_id: None,
                    cvss_score: Some(5.4),
                    discovered_at: Utc::now(),
                    false_positive: false,
                    metadata: HashMap::new(),
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Scan for information disclosure
    async fn scan_information_disclosure(&self, url: &str, target: &ScanTarget) -> GatewayResult<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test for sensitive information in responses
        if let Ok(response) = self.make_request(url, Method::GET, target).await {
            let sensitive_patterns = vec![
                ("password", "Password found in response"),
                ("api_key", "API key found in response"),
                ("secret", "Secret found in response"),
                ("token", "Token found in response"),
                ("private_key", "Private key found in response"),
            ];

            for (pattern, description) in sensitive_patterns {
                if response.to_lowercase().contains(pattern) {
                    vulnerabilities.push(Vulnerability {
                        id: Uuid::new_v4(),
                        vulnerability_type: VulnerabilityType::SensitiveDataExposure,
                        severity: VulnerabilitySeverity::High,
                        endpoint: url.to_string(),
                        method: Method::GET,
                        description: description.to_string(),
                        proof_of_concept: Some(format!("Pattern '{}' found in response", pattern)),
                        remediation: "Remove sensitive information from responses".to_string(),
                        cwe_id: Some(200),
                        cve_id: None,
                        cvss_score: Some(7.5),
                        discovered_at: Utc::now(),
                        false_positive: false,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Make HTTP request to target
    async fn make_request(&self, url: &str, method: Method, target: &ScanTarget) -> GatewayResult<String> {
        let reqwest_method = match method {
            Method::GET => reqwest::Method::GET,
            Method::POST => reqwest::Method::POST,
            Method::PUT => reqwest::Method::PUT,
            Method::DELETE => reqwest::Method::DELETE,
            Method::PATCH => reqwest::Method::PATCH,
            Method::HEAD => reqwest::Method::HEAD,
            Method::OPTIONS => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };
        let mut request = self.client.request(reqwest_method, url);

        // Add authentication
        match &target.auth {
            AuthMethod::None => {}
            AuthMethod::Bearer { token } => {
                request = request.bearer_auth(token);
            }
            AuthMethod::ApiKey { key } => {
                request = request.header("X-API-Key", key);
            }
            AuthMethod::Basic { username, password } => {
                request = request.basic_auth(username, Some(password));
            }
        }

        // Add custom headers
        for (key, value) in &target.headers {
            request = request.header(key, value);
        }

        let response = request.send().await
            .map_err(|e| GatewayError::internal(format!("Request failed: {}", e)))?;

        let body = response.text().await
            .map_err(|e| GatewayError::internal(format!("Failed to read response: {}", e)))?;

        Ok(body)
    }

    /// Make HTTP request with custom headers
    async fn make_request_with_headers(
        &self,
        url: &str,
        method: Method,
        target: &ScanTarget,
        headers: HeaderMap,
    ) -> GatewayResult<String> {
        let reqwest_method = match method {
            Method::GET => reqwest::Method::GET,
            Method::POST => reqwest::Method::POST,
            Method::PUT => reqwest::Method::PUT,
            Method::DELETE => reqwest::Method::DELETE,
            Method::PATCH => reqwest::Method::PATCH,
            Method::HEAD => reqwest::Method::HEAD,
            Method::OPTIONS => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };
        let mut request = self.client.request(reqwest_method, url);

        // Add authentication
        match &target.auth {
            AuthMethod::None => {}
            AuthMethod::Bearer { token } => {
                request = request.bearer_auth(token);
            }
            AuthMethod::ApiKey { key } => {
                request = request.header("X-API-Key", key);
            }
            AuthMethod::Basic { username, password } => {
                request = request.basic_auth(username, Some(password));
            }
        }

        // Add custom headers from target
        for (key, value) in &target.headers {
            request = request.header(key, value);
        }

        // Add additional headers
        let mut reqwest_headers = reqwest::header::HeaderMap::new();
        for (key, value) in headers.iter() {
            if let (Ok(name), Ok(val)) = (reqwest::header::HeaderName::from_bytes(key.as_str().as_bytes()), reqwest::header::HeaderValue::from_bytes(value.as_bytes())) {
                reqwest_headers.insert(name, val);
            }
        }
        request = request.headers(reqwest_headers);

        let response = request.send().await
            .map_err(|e| GatewayError::internal(format!("Request failed: {}", e)))?;

        let body = response.text().await
            .map_err(|e| GatewayError::internal(format!("Failed to read response: {}", e)))?;

        Ok(body)
    }

    /// Detect SQL injection in response
    async fn detect_sql_injection_response(&self, response: &str) -> bool {
        let sql_error_patterns = vec![
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "SQLSTATE",
        ];

        sql_error_patterns.iter().any(|pattern| response.contains(pattern))
    }

    /// Send notifications for discovered vulnerabilities
    async fn send_notifications(
        &self,
        config: &NotificationConfig,
        vulnerabilities: &[Vulnerability],
    ) -> GatewayResult<()> {
        // Filter vulnerabilities by severity threshold
        let filtered_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| v.severity as u8 >= config.severity_threshold as u8)
            .collect();

        if filtered_vulns.is_empty() {
            return Ok(());
        }

        // Send email notifications
        if let Some(email_config) = &config.email {
            self.send_email_notification(email_config, &filtered_vulns).await?;
        }

        // Send webhook notifications
        if let Some(webhook_config) = &config.webhook {
            self.send_webhook_notification(webhook_config, &filtered_vulns).await?;
        }

        Ok(())
    }

    /// Send email notification
    async fn send_email_notification(
        &self,
        _config: &EmailConfig,
        _vulnerabilities: &[&Vulnerability],
    ) -> GatewayResult<()> {
        // Email sending implementation would go here
        // For now, just log
        tracing::info!("Email notification would be sent");
        Ok(())
    }

    /// Send webhook notification
    async fn send_webhook_notification(
        &self,
        config: &WebhookConfig,
        vulnerabilities: &[&Vulnerability],
    ) -> GatewayResult<()> {
        let payload = serde_json::json!({
            "event": "vulnerabilities_detected",
            "timestamp": Utc::now(),
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total": vulnerabilities.len(),
                "critical": vulnerabilities.iter().filter(|v| matches!(v.severity, VulnerabilitySeverity::Critical)).count(),
                "high": vulnerabilities.iter().filter(|v| matches!(v.severity, VulnerabilitySeverity::High)).count(),
                "medium": vulnerabilities.iter().filter(|v| matches!(v.severity, VulnerabilitySeverity::Medium)).count(),
                "low": vulnerabilities.iter().filter(|v| matches!(v.severity, VulnerabilitySeverity::Low)).count(),
            }
        });

        let mut request = self.client.post(&config.url).json(&payload);

        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        let response = request.send().await
            .map_err(|e| GatewayError::internal(format!("Webhook request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(GatewayError::internal("Webhook notification failed"));
        }

        tracing::info!(webhook_url = %config.url, "Webhook notification sent");
        Ok(())
    }

    /// Initialize vulnerability database with default patterns
    async fn initialize_vulnerability_database(&self) -> GatewayResult<()> {
        let mut db = self.vulnerability_db.write().await;

        // Add default vulnerability patterns
        db.patterns.push(VulnerabilityPattern {
            id: Uuid::new_v4(),
            name: "SQL Injection".to_string(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            method_pattern: None,
            path_pattern: None,
            header_patterns: HashMap::new(),
            body_pattern: None,
            response_patterns: vec![ResponsePattern {
                status_code: Some(500),
                header_patterns: HashMap::new(),
                body_pattern: Some("SQL syntax".to_string()),
                response_time_threshold: None,
            }],
            severity: VulnerabilitySeverity::High,
        });

        db.signatures.push(VulnerabilitySignature {
            id: Uuid::new_v4(),
            name: "SQL Error Pattern".to_string(),
            regex_pattern: r"(?i)(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL|SQLite|SQLSTATE)".to_string(),
            vulnerability_type: VulnerabilityType::SqlInjection,
            severity: VulnerabilitySeverity::High,
            description: "SQL database error message detected".to_string(),
        });

        db.last_updated = Utc::now();
        Ok(())
    }

    /// Get scan result
    pub async fn get_scan_result(&self, scan_id: Uuid) -> Option<ScanResult> {
        self.scan_results.get(&scan_id).map(|r| r.clone())
    }

    /// List scan results
    pub async fn list_scan_results(&self, limit: usize) -> Vec<ScanResult> {
        self.scan_results.iter()
            .take(limit)
            .map(|r| r.clone())
            .collect()
    }

    /// Get scan progress
    pub async fn get_scan_progress(&self, scan_id: Uuid) -> Option<ScanProgress> {
        let active_scans = self.active_scans.lock().await;
        active_scans.get(&scan_id).cloned()
    }

    /// Cancel scan
    pub async fn cancel_scan(&self, scan_id: Uuid) -> GatewayResult<()> {
        {
            let mut active_scans = self.active_scans.lock().await;
            active_scans.remove(&scan_id);
        }

        if let Some(mut result) = self.scan_results.get_mut(&scan_id) {
            result.status = ScanStatus::Cancelled;
            result.completed_at = Some(Utc::now());
        }

        tracing::info!(scan_id = %scan_id, "Security scan cancelled");
        Ok(())
    }

    /// Add scan configuration
    pub async fn add_scan_config(&self, name: String, config: ScanConfig) -> GatewayResult<()> {
        let mut configs = self.scan_configs.write().await;
        configs.insert(name, config);
        Ok(())
    }

    /// Get scan configuration
    pub async fn get_scan_config(&self, name: &str) -> Option<ScanConfig> {
        let configs = self.scan_configs.read().await;
        configs.get(name).cloned()
    }

    /// List scan configurations
    pub async fn list_scan_configs(&self) -> Vec<(String, ScanConfig)> {
        let configs = self.scan_configs.read().await;
        configs.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

impl Clone for SecurityScanner {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            scan_configs: self.scan_configs.clone(),
            scan_results: self.scan_results.clone(),
            vulnerability_db: self.vulnerability_db.clone(),
            active_scans: self.active_scans.clone(),
        }
    }
}

// ============================================================================
// Security Scanner State and Router
// ============================================================================

/// Security scanner state
#[derive(Clone)]
pub struct SecurityScannerState {
    pub scanner: SecurityScanner,
}

impl SecurityScannerState {
    pub fn new() -> Self {
        Self {
            scanner: SecurityScanner::new(),
        }
    }
}

/// Create security scanner router
pub fn create_security_scanner_router(state: SecurityScannerState) -> Router {
    Router::new()
        // Scan management
        .route("/scans", post(start_security_scan))
        .route("/scans", get(list_security_scans))
        .route("/scans/:scan_id", get(get_security_scan))
        .route("/scans/:scan_id/progress", get(get_scan_progress))
        .route("/scans/:scan_id/cancel", post(cancel_security_scan))
        
        // Scan configurations
        .route("/scan-configs", post(create_scan_config))
        .route("/scan-configs", get(list_scan_configs))
        .route("/scan-configs/:name", get(get_scan_config))
        
        // Vulnerability management
        .route("/vulnerabilities", get(list_vulnerabilities))
        .route("/vulnerabilities/:vuln_id/false-positive", post(mark_false_positive))
        
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct StartScanRequest {
    pub config_name: String,
}

#[derive(Debug, Serialize)]
pub struct StartScanResponse {
    pub scan_id: Uuid,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateScanConfigRequest {
    pub name: String,
    pub config: ScanConfig,
}

#[derive(Debug, Deserialize)]
pub struct ListScansQuery {
    pub status: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct MarkFalsePositiveRequest {
    pub reason: String,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Start security scan
async fn start_security_scan(
    State(state): State<SecurityScannerState>,
    Json(request): Json<StartScanRequest>,
) -> GatewayResult<Json<StartScanResponse>> {
    let scan_id = state.scanner.start_scan(&request.config_name).await?;
    
    Ok(Json(StartScanResponse {
        scan_id,
        status: ScanStatus::Running,
        started_at: Utc::now(),
    }))
}

/// List security scans
async fn list_security_scans(
    State(state): State<SecurityScannerState>,
    Query(query): Query<ListScansQuery>,
) -> GatewayResult<Json<Vec<ScanResult>>> {
    let limit = query.limit.unwrap_or(50);
    let results = state.scanner.list_scan_results(limit).await;
    
    // Filter by status if specified
    let filtered_results = if let Some(status_str) = query.status {
        let status = match status_str.as_str() {
            "running" => ScanStatus::Running,
            "completed" => ScanStatus::Completed,
            "failed" => ScanStatus::Failed,
            "cancelled" => ScanStatus::Cancelled,
            _ => return Err(GatewayError::invalid_input("Invalid status filter")),
        };
        
        results.into_iter()
            .filter(|r| matches!(&r.status, &status))
            .collect()
    } else {
        results
    };
    
    Ok(Json(filtered_results))
}

/// Get security scan
async fn get_security_scan(
    State(state): State<SecurityScannerState>,
    Path(scan_id): Path<Uuid>,
) -> GatewayResult<Json<ScanResult>> {
    let result = state.scanner.get_scan_result(scan_id).await
        .ok_or_else(|| GatewayError::not_found("Scan not found"))?;
    
    Ok(Json(result))
}

/// Get scan progress
async fn get_scan_progress(
    State(state): State<SecurityScannerState>,
    Path(scan_id): Path<Uuid>,
) -> GatewayResult<Json<ScanProgress>> {
    let progress = state.scanner.get_scan_progress(scan_id).await
        .ok_or_else(|| GatewayError::not_found("Scan not found or not running"))?;
    
    Ok(Json(progress))
}

/// Cancel security scan
async fn cancel_security_scan(
    State(state): State<SecurityScannerState>,
    Path(scan_id): Path<Uuid>,
) -> GatewayResult<StatusCode> {
    state.scanner.cancel_scan(scan_id).await?;
    Ok(StatusCode::OK)
}

/// Create scan configuration
async fn create_scan_config(
    State(state): State<SecurityScannerState>,
    Json(request): Json<CreateScanConfigRequest>,
) -> GatewayResult<StatusCode> {
    state.scanner.add_scan_config(request.name, request.config).await?;
    Ok(StatusCode::CREATED)
}

/// List scan configurations
async fn list_scan_configs(
    State(state): State<SecurityScannerState>,
) -> GatewayResult<Json<Vec<(String, ScanConfig)>>> {
    let configs = state.scanner.list_scan_configs().await;
    Ok(Json(configs))
}

/// Get scan configuration
async fn get_scan_config(
    State(state): State<SecurityScannerState>,
    Path(name): Path<String>,
) -> GatewayResult<Json<ScanConfig>> {
    let config = state.scanner.get_scan_config(&name).await
        .ok_or_else(|| GatewayError::not_found("Scan configuration not found"))?;
    
    Ok(Json(config))
}

/// List vulnerabilities
async fn list_vulnerabilities(
    State(state): State<SecurityScannerState>,
    Query(query): Query<HashMap<String, String>>,
) -> GatewayResult<Json<Vec<Vulnerability>>> {
    let limit = query.get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(100);
    
    let results = state.scanner.list_scan_results(limit).await;
    let vulnerabilities: Vec<Vulnerability> = results.into_iter()
        .flat_map(|r| r.vulnerabilities)
        .collect();
    
    Ok(Json(vulnerabilities))
}

/// Mark vulnerability as false positive
async fn mark_false_positive(
    State(_state): State<SecurityScannerState>,
    Path(_vuln_id): Path<Uuid>,
    Json(_request): Json<MarkFalsePositiveRequest>,
) -> GatewayResult<StatusCode> {
    // Would update vulnerability record
    Ok(StatusCode::OK)
}