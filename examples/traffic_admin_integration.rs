//! # Traffic Admin Integration Example
//!
//! This example demonstrates how to integrate and use the traffic management
//! admin endpoints in a gateway application.

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

// Import the traffic management components
use gateway::traffic::{
    TrafficManager, TrafficConfig, BackpressureConfig, ThrottleConfig,
    PriorityConfig, ShutdownConfig,
    admin::{TrafficAdminRouter, TrafficAdminState},
};
use gateway::admin::{AdminRouter, AdminState, RuntimeConfigManager, ConfigAudit};
use gateway::core::config::GatewayConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::init();

    // Create traffic manager with default configuration
    let traffic_config = TrafficConfig {
        queue: BackpressureConfig {
            max_queue_size: 5000,
            backpressure_threshold: 0.75,
            timeout: std::time::Duration::from_secs(30),
            priority_levels: 3,
        },
        shaping: ThrottleConfig {
            global_rps_limit: Some(1000),
            per_client_rps_limit: Some(100),
            burst_size: 50,
            window_size: std::time::Duration::from_secs(1),
        },
        priority: PriorityConfig {
            enabled: true,
            default_priority: 2,
            rules: vec![],
        },
        shutdown: ShutdownConfig {
            grace_period: std::time::Duration::from_secs(30),
            drain_timeout: std::time::Duration::from_secs(10),
            force_timeout: std::time::Duration::from_secs(60),
        },
        splitting: vec![],
    };

    let traffic_manager = Arc::new(TrafficManager::new(traffic_config).await?);

    // Create admin components
    let config_manager = Arc::new(RuntimeConfigManager::new(GatewayConfig::default()).await?);
    let audit = Arc::new(ConfigAudit::new().await?);

    // Create admin state with traffic management enabled
    let admin_state = AdminState {
        config_manager,
        audit,
        service_management: None,
        load_balancer: None,
        traffic_management: Some(TrafficAdminState {
            traffic_manager: traffic_manager.clone(),
        }),
    };

    // Create the main application router
    let app = Router::new()
        // Main application routes
        .route("/", get(root_handler))
        .route("/api/status", get(status_handler))
        
        // Admin routes (including traffic management)
        .nest("/admin", AdminRouter::create_router(admin_state))
        
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
                .into_inner(),
        )
        .with_state(AppState {
            traffic_manager: traffic_manager.clone(),
        });

    // Start the server
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("🚀 Gateway server starting on http://0.0.0.0:8080");
    println!("📊 Admin interface available at http://0.0.0.0:8080/admin");
    println!("🚦 Traffic management endpoints at http://0.0.0.0:8080/admin/traffic");
    
    // Print some example curl commands
    print_example_commands();

    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    traffic_manager: Arc<TrafficManager>,
}

async fn root_handler() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Gateway with Traffic Management Admin API",
        "version": "1.0.0",
        "admin_endpoints": {
            "traffic_config": "/admin/traffic/config",
            "queue_management": "/admin/traffic/queue",
            "traffic_shaping": "/admin/traffic/shaping",
            "priority_rules": "/admin/traffic/priority",
            "ab_testing": "/admin/traffic/ab-tests",
            "traffic_splitting": "/admin/traffic/splits",
            "graceful_shutdown": "/admin/traffic/shutdown",
            "status": "/admin/traffic/status"
        }
    }))
}

async fn status_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.traffic_manager.get_overall_status().await {
        Ok(status) => Ok(Json(json!({
            "status": "healthy",
            "traffic_status": status
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to get status",
                "details": e.to_string()
            })),
        )),
    }
}

fn print_example_commands() {
    println!("\n📋 Example API Commands:");
    println!("========================");
    
    println!("\n🔧 Get current traffic configuration:");
    println!("curl -X GET http://localhost:8080/admin/traffic/config");
    
    println!("\n📊 Get queue metrics:");
    println!("curl -X GET http://localhost:8080/admin/traffic/queue/metrics");
    
    println!("\n⚡ Update traffic shaping:");
    println!(r#"curl -X PUT http://localhost:8080/admin/traffic/shaping/config \
  -H "Content-Type: application/json" \
  -d '{{
    "config": {{
      "global_rps_limit": 2000,
      "per_client_rps_limit": 200,
      "burst_size": 100,
      "window_size": "1s"
    }},
    "changed_by": "admin"
  }}'"#);
    
    println!("\n🎯 Add priority rule:");
    println!(r#"curl -X POST http://localhost:8080/admin/traffic/priority/rules \
  -H "Content-Type: application/json" \
  -d '{{
    "rule": {{
      "id": "premium-users",
      "name": "Premium User Priority",
      "condition": "headers.user-tier == \"premium\"",
      "priority": 1,
      "enabled": true
    }},
    "changed_by": "admin"
  }}'"#);
    
    println!("\n🧪 Create A/B test:");
    println!(r#"curl -X POST http://localhost:8080/admin/traffic/ab-tests \
  -H "Content-Type: application/json" \
  -d '{{
    "config": {{
      "name": "homepage-test",
      "description": "Testing new homepage",
      "variants": [
        {{
          "name": "control",
          "weight": 50,
          "upstream": "homepage-v1"
        }},
        {{
          "name": "treatment",
          "weight": 50,
          "upstream": "homepage-v2"
        }}
      ],
      "traffic_allocation": 100,
      "duration": "7d"
    }},
    "changed_by": "product-team"
  }}'"#);
    
    println!("\n🛑 Initiate graceful shutdown:");
    println!(r#"curl -X POST http://localhost:8080/admin/traffic/shutdown/initiate \
  -H "Content-Type: application/json" \
  -d '{{
    "timeout": "60s",
    "changed_by": "ops-team",
    "reason": "Planned maintenance"
  }}'"#);
    
    println!("\n📈 Get comprehensive metrics:");
    println!("curl -X GET http://localhost:8080/admin/traffic/metrics");
    
    println!("\n💚 Check traffic health:");
    println!("curl -X GET http://localhost:8080/admin/traffic/health");
    
    println!("\n========================\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use serde_json::Value;

    #[tokio::test]
    async fn test_traffic_admin_endpoints() {
        // Create test server
        let traffic_manager = Arc::new(
            TrafficManager::new(TrafficConfig::default())
                .await
                .expect("Failed to create traffic manager")
        );

        let config_manager = Arc::new(
            RuntimeConfigManager::new(GatewayConfig::default())
                .await
                .expect("Failed to create config manager")
        );
        
        let audit = Arc::new(
            ConfigAudit::new()
                .await
                .expect("Failed to create audit")
        );

        let admin_state = AdminState {
            config_manager,
            audit,
            service_management: None,
            load_balancer: None,
            traffic_management: Some(TrafficAdminState {
                traffic_manager: traffic_manager.clone(),
            }),
        };

        let app = Router::new()
            .nest("/admin", AdminRouter::create_router(admin_state))
            .with_state(AppState { traffic_manager });

        let server = TestServer::new(app).unwrap();

        // Test getting traffic configuration
        let response = server.get("/admin/traffic/config").await;
        assert_eq!(response.status_code(), 200);
        
        let config: Value = response.json();
        assert!(config.get("config").is_some());

        // Test getting queue metrics
        let response = server.get("/admin/traffic/queue/metrics").await;
        assert_eq!(response.status_code(), 200);
        
        let metrics: Value = response.json();
        assert!(metrics.get("metrics").is_some());

        // Test getting traffic status
        let response = server.get("/admin/traffic/status").await;
        assert_eq!(response.status_code(), 200);
        
        let status: Value = response.json();
        assert!(status.get("status").is_some());

        // Test getting traffic health
        let response = server.get("/admin/traffic/health").await;
        assert_eq!(response.status_code(), 200);
        
        let health: Value = response.json();
        assert!(health.get("health").is_some());
    }

    #[tokio::test]
    async fn test_priority_rule_management() {
        // Similar setup as above...
        let traffic_manager = Arc::new(
            TrafficManager::new(TrafficConfig::default())
                .await
                .expect("Failed to create traffic manager")
        );

        let config_manager = Arc::new(
            RuntimeConfigManager::new(GatewayConfig::default())
                .await
                .expect("Failed to create config manager")
        );
        
        let audit = Arc::new(
            ConfigAudit::new()
                .await
                .expect("Failed to create audit")
        );

        let admin_state = AdminState {
            config_manager,
            audit,
            service_management: None,
            load_balancer: None,
            traffic_management: Some(TrafficAdminState {
                traffic_manager: traffic_manager.clone(),
            }),
        };

        let app = Router::new()
            .nest("/admin", AdminRouter::create_router(admin_state))
            .with_state(AppState { traffic_manager });

        let server = TestServer::new(app).unwrap();

        // Test adding a priority rule
        let rule_request = json!({
            "rule": {
                "id": "test-rule",
                "name": "Test Priority Rule",
                "condition": "headers.priority == \"high\"",
                "priority": 1,
                "enabled": true
            },
            "changed_by": "test-user"
        });

        let response = server
            .post("/admin/traffic/priority/rules")
            .json(&rule_request)
            .await;
        
        assert_eq!(response.status_code(), 200);
        
        let result: Value = response.json();
        assert_eq!(result["success"], true);
        assert_eq!(result["rule_id"], "test-rule");

        // Test getting priority rules
        let response = server.get("/admin/traffic/priority/rules").await;
        assert_eq!(response.status_code(), 200);
        
        let rules: Value = response.json();
        assert!(rules.get("rules").is_some());
    }
}