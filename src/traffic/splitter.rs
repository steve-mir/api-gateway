//! # Traffic Splitting for A/B Testing
//! 
//! This module implements traffic splitting capabilities for A/B testing,
//! canary deployments, and gradual rollouts.

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{IncomingRequest, ServiceInstance};
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Configuration for traffic splitting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitConfig {
    /// Unique identifier for this split configuration
    pub id: String,
    
    /// Human-readable name for this split
    pub name: String,
    
    /// Whether this split is currently active
    pub enabled: bool,
    
    /// Traffic split rules
    pub rules: Vec<SplitRule>,
    
    /// Default variant when no rules match
    pub default_variant: String,
    
    /// Split strategy (percentage, header-based, etc.)
    pub strategy: SplitStrategy,
    
    /// Start time for this split (optional)
    pub start_time: Option<SystemTime>,
    
    /// End time for this split (optional)
    pub end_time: Option<SystemTime>,
    
    /// Sticky session configuration
    pub sticky_sessions: Option<StickySessionConfig>,
}

/// Traffic split rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitRule {
    /// Rule name for identification
    pub name: String,
    
    /// Conditions that must be met for this rule to apply
    pub conditions: Vec<SplitCondition>,
    
    /// Variant to route to when conditions are met
    pub variant: String,
    
    /// Weight/percentage for this rule (0-100)
    pub weight: f32,
    
    /// Whether this rule is enabled
    pub enabled: bool,
}

/// Condition for traffic splitting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SplitCondition {
    /// Match requests from specific user IDs
    UserId(Vec<String>),
    
    /// Match requests with specific header values
    Header { name: String, values: Vec<String> },
    
    /// Match requests from specific IP addresses or CIDR blocks
    IpAddress(Vec<String>),
    
    /// Match requests with specific query parameters
    QueryParam { name: String, values: Vec<String> },
    
    /// Match requests from specific user agents
    UserAgent(Vec<String>),
    
    /// Match requests with specific authentication roles
    UserRole(Vec<String>),
    
    /// Match requests during specific time windows
    TimeWindow { start_hour: u8, end_hour: u8 },
    
    /// Match requests based on geographic location
    GeoLocation(Vec<String>),
    
    /// Match requests based on percentage (for gradual rollouts)
    Percentage(f32),
    
    /// Custom condition based on request attributes
    Custom { attribute: String, values: Vec<String> },
}

/// Traffic splitting strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SplitStrategy {
    /// Percentage-based splitting
    Percentage,
    
    /// Header-based splitting
    HeaderBased { header_name: String },
    
    /// User ID-based splitting (consistent hashing)
    UserIdBased,
    
    /// IP-based splitting (consistent hashing)
    IpBased,
    
    /// Random splitting
    Random,
    
    /// Weighted random splitting
    WeightedRandom,
}

/// Sticky session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickySessionConfig {
    /// Cookie name for sticky sessions
    pub cookie_name: String,
    
    /// Cookie expiration time
    pub cookie_ttl: Duration,
    
    /// Whether to use secure cookies
    pub secure_cookie: bool,
    
    /// Cookie domain
    pub cookie_domain: Option<String>,
}

/// A/B test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestConfig {
    /// Test identifier
    pub test_id: String,
    
    /// Test name
    pub name: String,
    
    /// Test description
    pub description: String,
    
    /// Test variants with their configurations
    pub variants: HashMap<String, VariantConfig>,
    
    /// Traffic allocation percentages
    pub traffic_allocation: HashMap<String, f32>,
    
    /// Test start time
    pub start_time: SystemTime,
    
    /// Test end time
    pub end_time: SystemTime,
    
    /// Success metrics to track
    pub success_metrics: Vec<String>,
    
    /// Whether the test is currently active
    pub active: bool,
}

/// Variant configuration for A/B testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantConfig {
    /// Variant name
    pub name: String,
    
    /// Service instances for this variant
    pub service_instances: Vec<ServiceInstance>,
    
    /// Configuration overrides for this variant
    pub config_overrides: HashMap<String, serde_json::Value>,
    
    /// Feature flags for this variant
    pub feature_flags: HashMap<String, bool>,
}

/// Metrics for traffic splitting
#[derive(Debug, Clone)]
pub struct SplitMetrics {
    /// Total requests processed
    pub total_requests: Arc<AtomicU64>,
    
    /// Requests per variant
    pub variant_requests: Arc<std::sync::RwLock<HashMap<String, AtomicU64>>>,
    
    /// Split decisions made
    pub split_decisions: Arc<AtomicU64>,
    
    /// Sticky session hits
    pub sticky_session_hits: Arc<AtomicU64>,
    
    /// Sticky session misses
    pub sticky_session_misses: Arc<AtomicU64>,
}

impl Default for SplitMetrics {
    fn default() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            variant_requests: Arc::new(std::sync::RwLock::new(HashMap::new())),
            split_decisions: Arc::new(AtomicU64::new(0)),
            sticky_session_hits: Arc::new(AtomicU64::new(0)),
            sticky_session_misses: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Traffic splitter for A/B testing and canary deployments
pub struct TrafficSplitter {
    splits: Arc<std::sync::RwLock<HashMap<String, SplitConfig>>>,
    ab_tests: Arc<std::sync::RwLock<HashMap<String, ABTestConfig>>>,
    metrics: SplitMetrics,
}

impl TrafficSplitter {
    /// Create a new traffic splitter
    pub fn new() -> Self {
        Self {
            splits: Arc::new(std::sync::RwLock::new(HashMap::new())),
            ab_tests: Arc::new(std::sync::RwLock::new(HashMap::new())),
            metrics: SplitMetrics::default(),
        }
    }
    
    /// Add a traffic split configuration
    pub async fn add_split(&self, split: SplitConfig) -> GatewayResult<()> {
        let mut splits = self.splits.write().unwrap();
        splits.insert(split.id.clone(), split.clone());
        info!("Added traffic split configuration: {}", split.name);
        Ok(())
    }
    
    /// Remove a traffic split configuration
    pub async fn remove_split(&self, split_id: &str) -> GatewayResult<bool> {
        let mut splits = self.splits.write().unwrap();
        let removed = splits.remove(split_id).is_some();
        if removed {
            info!("Removed traffic split configuration: {}", split_id);
        }
        Ok(removed)
    }
    
    /// Add an A/B test configuration
    pub async fn add_ab_test(&self, test: ABTestConfig) -> GatewayResult<()> {
        let mut tests = self.ab_tests.write().unwrap();
        tests.insert(test.test_id.clone(), test.clone());
        info!("Added A/B test configuration: {}", test.name);
        Ok(())
    }
    
    /// Determine which variant a request should be routed to
    pub async fn determine_variant(&self, request: &IncomingRequest, split_id: &str) -> GatewayResult<String> {
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        
        let splits = self.splits.read().unwrap();
        let split = splits.get(split_id)
            .ok_or_else(|| GatewayError::Configuration(format!("Split configuration not found: {}", split_id)))?;
        
        if !split.enabled {
            return Ok(split.default_variant.clone());
        }
        
        // Check if split is within time window
        if !self.is_split_active(split) {
            return Ok(split.default_variant.clone());
        }
        
        // Check for sticky session first
        if let Some(sticky_config) = &split.sticky_sessions {
            if let Some(variant) = self.check_sticky_session(request, sticky_config).await? {
                self.metrics.sticky_session_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(variant);
            } else {
                self.metrics.sticky_session_misses.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Apply split rules
        for rule in &split.rules {
            if !rule.enabled {
                continue;
            }
            
            if self.matches_rule_conditions(request, rule).await? {
                let variant = self.apply_split_strategy(request, rule, &split.strategy).await?;
                self.record_variant_request(&variant);
                self.metrics.split_decisions.fetch_add(1, Ordering::Relaxed);
                
                debug!("Request routed to variant '{}' via rule '{}'", variant, rule.name);
                return Ok(variant);
            }
        }
        
        // No rules matched, use default variant
        let variant = split.default_variant.clone();
        self.record_variant_request(&variant);
        
        debug!("Request routed to default variant '{}'", variant);
        Ok(variant)
    }
    
    /// Check if a split configuration is currently active
    fn is_split_active(&self, split: &SplitConfig) -> bool {
        let now = SystemTime::now();
        
        if let Some(start_time) = split.start_time {
            if now < start_time {
                return false;
            }
        }
        
        if let Some(end_time) = split.end_time {
            if now > end_time {
                return false;
            }
        }
        
        true
    }
    
    /// Check for sticky session variant
    async fn check_sticky_session(&self, request: &IncomingRequest, sticky_config: &StickySessionConfig) -> GatewayResult<Option<String>> {
        // Look for sticky session cookie in request headers
        if let Some(cookie_header) = request.header("cookie") {
            if let Some(variant) = self.extract_variant_from_cookie(cookie_header, &sticky_config.cookie_name) {
                return Ok(Some(variant));
            }
        }
        
        Ok(None)
    }
    
    /// Extract variant from cookie value
    fn extract_variant_from_cookie(&self, cookie_header: &str, cookie_name: &str) -> Option<String> {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=') {
                if name.trim() == cookie_name {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }
    
    /// Check if request matches rule conditions
    async fn matches_rule_conditions(&self, request: &IncomingRequest, rule: &SplitRule) -> GatewayResult<bool> {
        for condition in &rule.conditions {
            if !self.matches_condition(request, condition).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    /// Check if request matches a specific condition
    async fn matches_condition(&self, request: &IncomingRequest, condition: &SplitCondition) -> GatewayResult<bool> {
        match condition {
            SplitCondition::UserId(user_ids) => {
                // For IncomingRequest, we'll check for user ID in headers
                if let Some(user_id) = request.header("x-user-id") {
                    Ok(user_ids.contains(&user_id.to_string()))
                } else {
                    Ok(false)
                }
            }
            
            SplitCondition::Header { name, values } => {
                if let Some(header_value) = request.header(name) {
                    Ok(values.contains(&header_value.to_string()))
                } else {
                    Ok(false)
                }
            }
            
            SplitCondition::IpAddress(ip_addresses) => {
                // In a real implementation, you'd extract the client IP and check against CIDR blocks
                let client_ip = self.extract_client_ip(request);
                Ok(client_ip.map_or(false, |ip| ip_addresses.contains(&ip)))
            }
            
            SplitCondition::QueryParam { name, values } => {
                // Parse query parameters from request path
                if let Some(query_value) = self.extract_query_param(request, name) {
                    Ok(values.contains(&query_value))
                } else {
                    Ok(false)
                }
            }
            
            SplitCondition::UserAgent(user_agents) => {
                if let Some(user_agent) = request.header("user-agent") {
                    Ok(user_agents.iter().any(|ua| user_agent.contains(ua)))
                } else {
                    Ok(false)
                }
            }
            
            SplitCondition::UserRole(roles) => {
                // For IncomingRequest, we'll check for role in headers
                if let Some(user_role) = request.header("x-user-role") {
                    Ok(roles.contains(&user_role.to_string()))
                } else {
                    Ok(false)
                }
            }
            
            SplitCondition::TimeWindow { start_hour, end_hour } => {
                let current_hour = chrono::Utc::now().hour() as u8;
                Ok(current_hour >= *start_hour && current_hour <= *end_hour)
            }
            
            SplitCondition::GeoLocation(locations) => {
                // In a real implementation, you'd use GeoIP lookup
                let geo_location = self.extract_geo_location(request);
                Ok(geo_location.map_or(false, |loc| locations.contains(&loc)))
            }
            
            SplitCondition::Percentage(percentage) => {
                let hash = self.calculate_request_hash(request);
                let request_percentage = (hash % 100) as f32;
                Ok(request_percentage < *percentage)
            }
            
            SplitCondition::Custom { attribute, values } => {
                // Custom condition logic would be implemented here
                // For now, return false as placeholder
                Ok(false)
            }
        }
    }
    
    /// Apply split strategy to determine variant
    async fn apply_split_strategy(&self, request: &IncomingRequest, rule: &SplitRule, strategy: &SplitStrategy) -> GatewayResult<String> {
        match strategy {
            SplitStrategy::Percentage => {
                let hash = self.calculate_request_hash(request);
                let percentage = (hash % 100) as f32;
                
                if percentage < rule.weight {
                    Ok(rule.variant.clone())
                } else {
                    // This would need to be handled differently in a real implementation
                    // For now, return the rule variant
                    Ok(rule.variant.clone())
                }
            }
            
            SplitStrategy::HeaderBased { header_name } => {
                if let Some(header_value) = request.header(header_name) {
                    // Use header value to determine variant
                    let hash = self.calculate_string_hash(header_value);
                    if ((hash % 100) as f32) < rule.weight {
                        return Ok(rule.variant.clone());
                    } else {
                        return Ok(rule.variant.clone());
                    }
                } else {
                    Ok(rule.variant.clone())
                }
            }
            
            SplitStrategy::UserIdBased => {
                // For IncomingRequest, we'll check for user ID in headers
                if let Some(user_id) = request.header("x-user-id") {
                    let hash = self.calculate_string_hash(user_id);
                    if ((hash % 100) as f32) < rule.weight {
                        return Ok(rule.variant.clone());
                    } else {
                        return Ok(rule.variant.clone());
                    }
                } else {
                    Ok(rule.variant.clone())
                }
            }
            
            SplitStrategy::IpBased => {
                if let Some(ip) = self.extract_client_ip(request) {
                    let hash = self.calculate_string_hash(&ip);
                    if ((hash % 100) as f32) < rule.weight {
                        return Ok(rule.variant.clone());
                    } else {
                        return Ok(rule.variant.clone());
                    }
                } else {
                    Ok(rule.variant.clone())
                }
            }
            
            SplitStrategy::Random => {
                let random_value = fastrand::f32() * 100.0;
                if random_value < rule.weight {
                    Ok(rule.variant.clone())
                } else {
                    Ok(rule.variant.clone())
                }
            }
            
            SplitStrategy::WeightedRandom => {
                // For weighted random, we'd need access to all variants and their weights
                // For now, use simple random
                let random_value = fastrand::f32() * 100.0;
                if random_value < rule.weight {
                    Ok(rule.variant.clone())
                } else {
                    Ok(rule.variant.clone())
                }
            }
        }
    }
    
    /// Calculate a hash for the request (for consistent splitting)
    fn calculate_request_hash(&self, request: &IncomingRequest) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        request.id.hash(&mut hasher);
        
        // Include user ID if available for consistency
        if let Some(user_id) = request.header("x-user-id") {
            user_id.hash(&mut hasher);
        }
        
        hasher.finish()
    }
    
    /// Calculate a hash for a string
    fn calculate_string_hash(&self, value: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Extract client IP from request
    fn extract_client_ip(&self, request: &IncomingRequest) -> Option<String> {
        // Check various headers for client IP
        if let Some(forwarded_for) = request.header("x-forwarded-for") {
            return Some(forwarded_for.split(',').next().unwrap_or("").trim().to_string());
        }
        
        if let Some(real_ip) = request.header("x-real-ip") {
            return Some(real_ip.to_string());
        }
        
        // Use remote address as fallback
        Some(request.remote_addr.ip().to_string())
    }
    
    /// Extract query parameter from request
    fn extract_query_param(&self, request: &IncomingRequest, param_name: &str) -> Option<String> {
        if let Some(query_string) = request.query() {
            for param in query_string.split('&') {
                if let Some((name, value)) = param.split_once('=') {
                    if name == param_name {
                        return Some(value.to_string());
                    }
                }
            }
        }
        
        None
    }
    
    /// Extract geographic location from request
    fn extract_geo_location(&self, _request: &IncomingRequest) -> Option<String> {
        // In a real implementation, you'd use GeoIP lookup
        // For now, return None
        None
    }
    
    /// Record a request for a specific variant
    fn record_variant_request(&self, variant: &str) {
        let mut variant_requests = self.metrics.variant_requests.write().unwrap();
        variant_requests
            .entry(variant.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get traffic splitting metrics
    pub fn metrics(&self) -> &SplitMetrics {
        &self.metrics
    }
    
    /// Get variant request counts
    pub fn get_variant_counts(&self) -> HashMap<String, u64> {
        let variant_requests = self.metrics.variant_requests.read().unwrap();
        variant_requests
            .iter()
            .map(|(variant, count)| (variant.clone(), count.load(Ordering::Relaxed)))
            .collect()
    }
    
    /// List all active splits
    pub fn list_splits(&self) -> Vec<SplitConfig> {
        let splits = self.splits.read().unwrap();
        splits.values().cloned().collect()
    }
    
    /// List all active A/B tests
    pub fn list_ab_tests(&self) -> Vec<ABTestConfig> {
        let tests = self.ab_tests.read().unwrap();
        tests.values().cloned().collect()
    }
    
    /// Update split configuration
    pub async fn update_split(&self, split: SplitConfig) -> GatewayResult<()> {
        let mut splits = self.splits.write().unwrap();
        splits.insert(split.id.clone(), split.clone());
        info!("Updated traffic split configuration: {}", split.name);
        Ok(())
    }
    
    /// Enable or disable a split
    pub async fn toggle_split(&self, split_id: &str, enabled: bool) -> GatewayResult<bool> {
        let mut splits = self.splits.write().unwrap();
        
        if let Some(split) = splits.get_mut(split_id) {
            split.enabled = enabled;
            info!("Toggled split '{}': {}", split_id, enabled);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Default for TrafficSplitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{AuthContext, RequestContext, Protocol};
    use std::collections::HashMap;
    use axum::http::{Method, HeaderMap, Version};
    
    fn create_test_request(user_id: Option<String>) -> IncomingRequest {
        let mut headers = HeaderMap::new();
        
        if let Some(uid) = user_id {
            headers.insert("x-user-id", uid.parse().unwrap());
        }
        
        IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/api/test".parse().unwrap(),
            Version::HTTP_11,
            headers,
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }
    
    #[tokio::test]
    async fn test_basic_traffic_splitting() {
        let splitter = TrafficSplitter::new();
        
        let split = SplitConfig {
            id: "test-split".to_string(),
            name: "Test Split".to_string(),
            enabled: true,
            rules: vec![
                SplitRule {
                    name: "variant-a".to_string(),
                    conditions: vec![SplitCondition::Percentage(50.0)],
                    variant: "variant-a".to_string(),
                    weight: 50.0,
                    enabled: true,
                }
            ],
            default_variant: "variant-b".to_string(),
            strategy: SplitStrategy::Percentage,
            start_time: None,
            end_time: None,
            sticky_sessions: None,
        };
        
        splitter.add_split(split).await.unwrap();
        
        let request = create_test_request(Some("user123".to_string()));
        let variant = splitter.determine_variant(&request, "test-split").await.unwrap();
        
        // Should return either variant-a or variant-b
        assert!(variant == "variant-a" || variant == "variant-b");
    }
    
    #[tokio::test]
    async fn test_user_id_condition() {
        let splitter = TrafficSplitter::new();
        
        let split = SplitConfig {
            id: "user-split".to_string(),
            name: "User Split".to_string(),
            enabled: true,
            rules: vec![
                SplitRule {
                    name: "specific-user".to_string(),
                    conditions: vec![SplitCondition::UserId(vec!["user123".to_string()])],
                    variant: "special-variant".to_string(),
                    weight: 100.0,
                    enabled: true,
                }
            ],
            default_variant: "default-variant".to_string(),
            strategy: SplitStrategy::UserIdBased,
            start_time: None,
            end_time: None,
            sticky_sessions: None,
        };
        
        splitter.add_split(split).await.unwrap();
        
        // Test with matching user
        let request1 = create_test_request(Some("user123".to_string()));
        let variant1 = splitter.determine_variant(&request1, "user-split").await.unwrap();
        assert_eq!(variant1, "special-variant");
        
        // Test with non-matching user
        let request2 = create_test_request(Some("user456".to_string()));
        let variant2 = splitter.determine_variant(&request2, "user-split").await.unwrap();
        assert_eq!(variant2, "default-variant");
    }
    
    #[tokio::test]
    async fn test_header_condition() {
        let splitter = TrafficSplitter::new();
        
        let split = SplitConfig {
            id: "header-split".to_string(),
            name: "Header Split".to_string(),
            enabled: true,
            rules: vec![
                SplitRule {
                    name: "beta-users".to_string(),
                    conditions: vec![SplitCondition::Header {
                        name: "x-beta-user".to_string(),
                        values: vec!["true".to_string()],
                    }],
                    variant: "beta-variant".to_string(),
                    weight: 100.0,
                    enabled: true,
                }
            ],
            default_variant: "stable-variant".to_string(),
            strategy: SplitStrategy::HeaderBased { header_name: "x-beta-user".to_string() },
            start_time: None,
            end_time: None,
            sticky_sessions: None,
        };
        
        splitter.add_split(split).await.unwrap();
        
        // Test with beta header
        let mut request1 = create_test_request(None);
        request1.headers.insert("x-beta-user".to_string(), "true".to_string());
        let variant1 = splitter.determine_variant(&request1, "header-split").await.unwrap();
        assert_eq!(variant1, "beta-variant");
        
        // Test without beta header
        let request2 = create_test_request(None);
        let variant2 = splitter.determine_variant(&request2, "header-split").await.unwrap();
        assert_eq!(variant2, "stable-variant");
    }
    
    #[tokio::test]
    async fn test_disabled_split() {
        let splitter = TrafficSplitter::new();
        
        let split = SplitConfig {
            id: "disabled-split".to_string(),
            name: "Disabled Split".to_string(),
            enabled: false, // Disabled
            rules: vec![],
            default_variant: "default-variant".to_string(),
            strategy: SplitStrategy::Random,
            start_time: None,
            end_time: None,
            sticky_sessions: None,
        };
        
        splitter.add_split(split).await.unwrap();
        
        let request = create_test_request(None);
        let variant = splitter.determine_variant(&request, "disabled-split").await.unwrap();
        
        // Should always return default variant when split is disabled
        assert_eq!(variant, "default-variant");
    }
}