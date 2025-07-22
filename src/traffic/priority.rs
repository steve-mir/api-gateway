//! # Request Prioritization System
//! 
//! This module implements request prioritization based on configurable criteria
//! such as client type, endpoint importance, authentication level, etc.

use crate::core::error::{GatewayError, GatewayResult};
use crate::core::types::{IncomingRequest, RequestContext};
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Request priority levels (higher number = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequestPriority {
    /// Lowest priority - background tasks, analytics
    Background = 1,
    /// Low priority - non-critical operations
    Low = 2,
    /// Normal priority - standard user requests
    Normal = 3,
    /// High priority - premium users, important operations
    High = 4,
    /// Critical priority - system operations, health checks
    Critical = 5,
    /// Emergency priority - security, alerts
    Emergency = 6,
}

impl Default for RequestPriority {
    fn default() -> Self {
        RequestPriority::Normal
    }
}

impl From<u8> for RequestPriority {
    fn from(value: u8) -> Self {
        match value {
            1 => RequestPriority::Background,
            2 => RequestPriority::Low,
            3 => RequestPriority::Normal,
            4 => RequestPriority::High,
            5 => RequestPriority::Critical,
            6 => RequestPriority::Emergency,
            _ => RequestPriority::Normal,
        }
    }
}

impl From<RequestPriority> for u8 {
    fn from(priority: RequestPriority) -> Self {
        priority as u8
    }
}

/// Configuration for request prioritization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityConfig {
    /// Default priority for requests
    pub default_priority: RequestPriority,
    
    /// Priority rules based on different criteria
    pub rules: Vec<PriorityRule>,
    
    /// Client-specific priority overrides
    pub client_priorities: HashMap<String, RequestPriority>,
    
    /// Endpoint-specific priority overrides
    pub endpoint_priorities: HashMap<String, RequestPriority>,
    
    /// Authentication level priorities
    pub auth_level_priorities: HashMap<String, RequestPriority>,
    
    /// Enable dynamic priority adjustment based on system load
    pub dynamic_adjustment: bool,
    
    /// Priority boost for requests that have been waiting longer
    pub aging_boost_enabled: bool,
    
    /// Time threshold for aging boost (in seconds)
    pub aging_threshold_secs: u64,
    
    /// Priority boost amount for aged requests
    pub aging_boost_amount: u8,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            default_priority: RequestPriority::Normal,
            rules: vec![
                // Health check endpoints get critical priority
                PriorityRule {
                    name: "health_checks".to_string(),
                    criteria: PriorityCriteria::PathPattern("/health*".to_string()),
                    priority: RequestPriority::Critical,
                    enabled: true,
                },
                // Admin endpoints get high priority
                PriorityRule {
                    name: "admin_endpoints".to_string(),
                    criteria: PriorityCriteria::PathPattern("/admin/*".to_string()),
                    priority: RequestPriority::High,
                    enabled: true,
                },
                // Authenticated users get higher priority
                PriorityRule {
                    name: "authenticated_users".to_string(),
                    criteria: PriorityCriteria::HasAuthentication,
                    priority: RequestPriority::High,
                    enabled: true,
                },
            ],
            client_priorities: HashMap::new(),
            endpoint_priorities: HashMap::new(),
            auth_level_priorities: HashMap::new(),
            dynamic_adjustment: true,
            aging_boost_enabled: true,
            aging_threshold_secs: 30,
            aging_boost_amount: 1,
        }
    }
}

/// Priority rule for determining request priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityRule {
    /// Rule name for identification
    pub name: String,
    
    /// Criteria for matching requests
    pub criteria: PriorityCriteria,
    
    /// Priority to assign when criteria matches
    pub priority: RequestPriority,
    
    /// Whether this rule is enabled
    pub enabled: bool,
}

/// Criteria for priority rule matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PriorityCriteria {
    /// Match requests from specific client ID
    ClientId(String),
    
    /// Match requests to specific path pattern (supports wildcards)
    PathPattern(String),
    
    /// Match requests with specific HTTP method
    HttpMethod(String),
    
    /// Match requests with specific header value
    HeaderValue { name: String, value: String },
    
    /// Match requests with authentication
    HasAuthentication,
    
    /// Match requests with specific authentication level
    AuthLevel(String),
    
    /// Match requests with specific user role
    UserRole(String),
    
    /// Match requests during specific time windows
    TimeWindow { start_hour: u8, end_hour: u8 },
    
    /// Match requests based on content type
    ContentType(String),
    
    /// Composite criteria (AND logic)
    And(Vec<PriorityCriteria>),
    
    /// Composite criteria (OR logic)
    Or(Vec<PriorityCriteria>),
    
    /// Negated criteria
    Not(Box<PriorityCriteria>),
}

/// Request priority manager
pub struct PriorityManager {
    config: Arc<PriorityConfig>,
}

impl PriorityManager {
    /// Create a new priority manager with the given configuration
    pub fn new(config: PriorityConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
    
    /// Determine the priority of a request based on configured rules
    pub async fn determine_priority(&self, request: &IncomingRequest) -> RequestPriority {
        let mut priority = self.config.default_priority;
        
        // Check client-specific priorities first
        if let Some(client_id) = self.extract_client_id(request) {
            if let Some(&client_priority) = self.config.client_priorities.get(&client_id) {
                priority = priority.max(client_priority);
                debug!("Applied client priority {} for client {}", client_priority as u8, client_id);
            }
        }
        
        // Check endpoint-specific priorities
        if let Some(&endpoint_priority) = self.config.endpoint_priorities.get(&request.path) {
            priority = priority.max(endpoint_priority);
            debug!("Applied endpoint priority {} for path {}", endpoint_priority as u8, request.path);
        }
        
        // Check authentication level priorities
        if let Some(auth_level) = self.extract_auth_level(request) {
            if let Some(&auth_priority) = self.config.auth_level_priorities.get(&auth_level) {
                priority = priority.max(auth_priority);
                debug!("Applied auth level priority {} for level {}", auth_priority as u8, auth_level);
            }
        }
        
        // Apply priority rules
        for rule in &self.config.rules {
            if rule.enabled && self.matches_criteria(&rule.criteria, request).await {
                priority = priority.max(rule.priority);
                debug!("Applied rule '{}' priority {}", rule.name, rule.priority as u8);
            }
        }
        
        // Apply dynamic adjustment if enabled
        if self.config.dynamic_adjustment {
            priority = self.apply_dynamic_adjustment(priority).await;
        }
        
        // Apply aging boost if enabled
        if self.config.aging_boost_enabled {
            priority = self.apply_aging_boost(priority, request).await;
        }
        
        debug!("Final priority for request {}: {}", request.id, priority as u8);
        priority
    }
    
    /// Check if a request matches the given criteria
    async fn matches_criteria(&self, criteria: &PriorityCriteria, request: &IncomingRequest) -> bool {
        match criteria {
            PriorityCriteria::ClientId(client_id) => {
                self.extract_client_id(request).map_or(false, |id| id == *client_id)
            }
            
            PriorityCriteria::PathPattern(pattern) => {
                self.matches_path_pattern(&request.path, pattern)
            }
            
            PriorityCriteria::HttpMethod(method) => {
                request.method.eq_ignore_ascii_case(method)
            }
            
            PriorityCriteria::HeaderValue { name, value } => {
                request.headers.get(name).map_or(false, |v| v == value)
            }
            
            PriorityCriteria::HasAuthentication => {
                // For IncomingRequest, we'll check for authorization header
                request.header("authorization").is_some()
            }
            
            PriorityCriteria::AuthLevel(level) => {
                self.extract_auth_level(request).map_or(false, |l| l == *level)
            }
            
            PriorityCriteria::UserRole(role) => {
                // For IncomingRequest, we'll check for role header
                request.header("x-user-role")
                    .map_or(false, |user_role| user_role == role)
            }
            
            PriorityCriteria::TimeWindow { start_hour, end_hour } => {
                let current_hour = chrono::Utc::now().hour() as u8;
                current_hour >= *start_hour && current_hour <= *end_hour
            }
            
            PriorityCriteria::ContentType(content_type) => {
                request.headers.get("content-type")
                    .map_or(false, |ct| ct.contains(content_type))
            }
            
            PriorityCriteria::And(criteria_list) => {
                for criterion in criteria_list {
                    if !self.matches_criteria(criterion, request).await {
                        return false;
                    }
                }
                true
            }
            
            PriorityCriteria::Or(criteria_list) => {
                for criterion in criteria_list {
                    if self.matches_criteria(criterion, request).await {
                        return true;
                    }
                }
                false
            }
            
            PriorityCriteria::Not(criterion) => {
                !self.matches_criteria(criterion, request).await
            }
        }
    }
    
    /// Extract client ID from request (from headers, auth context, etc.)
    fn extract_client_id(&self, request: &IncomingRequest) -> Option<String> {
        // Try to get client ID from various sources
        if let Some(client_id) = request.header("x-client-id") {
            return Some(client_id.to_string());
        }
        
        // Could also extract from JWT claims, API key, etc.
        // For now, use remote address as fallback
        Some(request.remote_addr.ip().to_string())
    }
    
    /// Extract authentication level from request
    fn extract_auth_level(&self, request: &IncomingRequest) -> Option<String> {
        // For now, we'll extract from headers since IncomingRequest doesn't have context
        if let Some(auth_level) = request.header("x-auth-level") {
            return Some(auth_level.to_string());
        }
        
        // Could also check for specific headers, tokens, etc.
        None
    }
    
    /// Check if a path matches a pattern (supports basic wildcards)
    fn matches_path_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else if pattern.contains('*') {
            // More complex pattern matching could be implemented here
            // For now, just do exact match if no trailing wildcard
            path == pattern
        } else {
            path == pattern
        }
    }
    
    /// Apply dynamic priority adjustment based on system load
    async fn apply_dynamic_adjustment(&self, priority: RequestPriority) -> RequestPriority {
        // In a real implementation, you'd check system metrics
        // For now, we'll simulate some basic logic
        
        // During high load, boost critical and emergency requests
        let system_load = self.get_system_load().await;
        
        if system_load > 0.8 {
            match priority {
                RequestPriority::Critical => RequestPriority::Emergency,
                RequestPriority::High => RequestPriority::Critical,
                _ => priority,
            }
        } else {
            priority
        }
    }
    
    /// Apply aging boost for requests that have been waiting
    async fn apply_aging_boost(&self, priority: RequestPriority, request: &IncomingRequest) -> RequestPriority {
        // For IncomingRequest, we'll use received_at as a proxy for queued_at
        let wait_time = request.received_at.elapsed();
        
        if wait_time.as_secs() >= self.config.aging_threshold_secs {
            let boost_amount = self.config.aging_boost_amount;
            let new_priority_value = (priority as u8).saturating_add(boost_amount).min(6);
            let boosted_priority = RequestPriority::from(new_priority_value);
            
            debug!("Applied aging boost to request {} (waited {:?}): {} -> {}", 
                   request.id, wait_time, priority as u8, boosted_priority as u8);
            
            return boosted_priority;
        }
        
        priority
    }
    
    /// Get current system load (placeholder implementation)
    async fn get_system_load(&self) -> f32 {
        // In a real implementation, this would check actual system metrics
        fastrand::f32() * 0.5 // Simulate 0-50% load
    }
    
    /// Create a priority rule for a specific client
    pub fn create_client_rule(client_id: String, priority: RequestPriority) -> PriorityRule {
        PriorityRule {
            name: format!("client_{}", client_id),
            criteria: PriorityCriteria::ClientId(client_id),
            priority,
            enabled: true,
        }
    }
    
    /// Create a priority rule for a specific endpoint pattern
    pub fn create_endpoint_rule(pattern: String, priority: RequestPriority) -> PriorityRule {
        PriorityRule {
            name: format!("endpoint_{}", pattern.replace('*', "wildcard")),
            criteria: PriorityCriteria::PathPattern(pattern),
            priority,
            enabled: true,
        }
    }
    
    /// Create a priority rule for authenticated users with specific role
    pub fn create_role_rule(role: String, priority: RequestPriority) -> PriorityRule {
        PriorityRule {
            name: format!("role_{}", role),
            criteria: PriorityCriteria::UserRole(role),
            priority,
            enabled: true,
        }
    }
    
    /// Update configuration dynamically
    pub async fn update_config(&mut self, new_config: PriorityConfig) {
        self.config = Arc::new(new_config);
        info!("Priority manager configuration updated");
    }
    
    /// Get current configuration
    pub fn config(&self) -> &PriorityConfig {
        &self.config
    }
    
    /// Add a new priority rule
    pub async fn add_rule(&mut self, rule: PriorityRule) {
        let mut config = (*self.config).clone();
        config.rules.push(rule);
        self.config = Arc::new(config);
        info!("Added new priority rule");
    }
    
    /// Remove a priority rule by name
    pub async fn remove_rule(&mut self, rule_name: &str) -> bool {
        let mut config = (*self.config).clone();
        let initial_len = config.rules.len();
        config.rules.retain(|rule| rule.name != rule_name);
        
        if config.rules.len() < initial_len {
            self.config = Arc::new(config);
            info!("Removed priority rule: {}", rule_name);
            true
        } else {
            false
        }
    }
    
    /// Enable or disable a priority rule
    pub async fn toggle_rule(&mut self, rule_name: &str, enabled: bool) -> bool {
        let mut config = (*self.config).clone();
        
        for rule in &mut config.rules {
            if rule.name == rule_name {
                rule.enabled = enabled;
                self.config = Arc::new(config);
                info!("Toggled priority rule '{}': {}", rule_name, enabled);
                return true;
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{AuthContext, RequestContext, IncomingRequest};
    use std::collections::HashMap;
    use axum::http::{Method, HeaderMap, Version};
    use std::net::SocketAddr;
    
    fn create_test_request(path: &str, method: &str) -> IncomingRequest {
        IncomingRequest::new(
            crate::core::types::Protocol::Http,
            method.parse().unwrap_or(Method::GET),
            path.parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }
    
    fn create_authenticated_request(path: &str, _roles: Vec<String>) -> IncomingRequest {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("x-user-role", "admin".parse().unwrap());
        
        IncomingRequest::new(
            crate::core::types::Protocol::Http,
            Method::GET,
            path.parse().unwrap(),
            Version::HTTP_11,
            headers,
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        )
    }
    
    #[tokio::test]
    async fn test_default_priority() {
        let config = PriorityConfig::default();
        let manager = PriorityManager::new(config);
        
        let request = create_test_request("/api/test", "GET");
        let priority = manager.determine_priority(&request).await;
        
        assert_eq!(priority, RequestPriority::Normal);
    }
    
    #[tokio::test]
    async fn test_path_pattern_matching() {
        let config = PriorityConfig {
            rules: vec![
                PriorityRule {
                    name: "health_check".to_string(),
                    criteria: PriorityCriteria::PathPattern("/health*".to_string()),
                    priority: RequestPriority::Critical,
                    enabled: true,
                }
            ],
            ..Default::default()
        };
        
        let manager = PriorityManager::new(config);
        
        let health_request = create_test_request("/health", "GET");
        let priority = manager.determine_priority(&health_request).await;
        assert_eq!(priority, RequestPriority::Critical);
        
        let health_check_request = create_test_request("/health/check", "GET");
        let priority = manager.determine_priority(&health_check_request).await;
        assert_eq!(priority, RequestPriority::Critical);
        
        let other_request = create_test_request("/api/users", "GET");
        let priority = manager.determine_priority(&other_request).await;
        assert_eq!(priority, RequestPriority::Normal);
    }
    
    #[tokio::test]
    async fn test_authentication_priority() {
        let config = PriorityConfig {
            rules: vec![
                PriorityRule {
                    name: "authenticated".to_string(),
                    criteria: PriorityCriteria::HasAuthentication,
                    priority: RequestPriority::High,
                    enabled: true,
                }
            ],
            ..Default::default()
        };
        
        let manager = PriorityManager::new(config);
        
        let auth_request = create_authenticated_request("/api/test", vec!["user".to_string()]);
        let priority = manager.determine_priority(&auth_request).await;
        assert_eq!(priority, RequestPriority::High);
        
        let unauth_request = create_test_request("/api/test", "GET");
        let priority = manager.determine_priority(&unauth_request).await;
        assert_eq!(priority, RequestPriority::Normal);
    }
    
    #[tokio::test]
    async fn test_role_based_priority() {
        let config = PriorityConfig {
            rules: vec![
                PriorityRule {
                    name: "admin_role".to_string(),
                    criteria: PriorityCriteria::UserRole("admin".to_string()),
                    priority: RequestPriority::Critical,
                    enabled: true,
                }
            ],
            ..Default::default()
        };
        
        let manager = PriorityManager::new(config);
        
        let admin_request = create_authenticated_request("/api/test", vec!["admin".to_string()]);
        let priority = manager.determine_priority(&admin_request).await;
        assert_eq!(priority, RequestPriority::Critical);
        
        let user_request = create_authenticated_request("/api/test", vec!["user".to_string()]);
        let priority = manager.determine_priority(&user_request).await;
        assert_eq!(priority, RequestPriority::Normal);
    }
    
    #[tokio::test]
    async fn test_composite_criteria() {
        let config = PriorityConfig {
            rules: vec![
                PriorityRule {
                    name: "admin_api".to_string(),
                    criteria: PriorityCriteria::And(vec![
                        PriorityCriteria::PathPattern("/admin/*".to_string()),
                        PriorityCriteria::UserRole("admin".to_string()),
                    ]),
                    priority: RequestPriority::Emergency,
                    enabled: true,
                }
            ],
            ..Default::default()
        };
        
        let manager = PriorityManager::new(config);
        
        // Should match both criteria
        let admin_api_request = create_authenticated_request("/admin/users", vec!["admin".to_string()]);
        let priority = manager.determine_priority(&admin_api_request).await;
        assert_eq!(priority, RequestPriority::Emergency);
        
        // Should not match (wrong path)
        let admin_other_request = create_authenticated_request("/api/users", vec!["admin".to_string()]);
        let priority = manager.determine_priority(&admin_other_request).await;
        assert_eq!(priority, RequestPriority::Normal);
        
        // Should not match (wrong role)
        let user_admin_request = create_authenticated_request("/admin/users", vec!["user".to_string()]);
        let priority = manager.determine_priority(&user_admin_request).await;
        assert_eq!(priority, RequestPriority::Normal);
    }
}