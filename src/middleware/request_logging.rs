use std::time::Instant;
use tracing::{info, warn};

pub struct RequestLoggingMiddleware {
    log_body: bool,
    log_headers: bool,
}

impl RequestLoggingMiddleware {
    pub fn new(log_body: bool, log_headers: bool) -> Self {
        Self {
            log_body,
            log_headers,
        }
    }

    pub fn log_request(&self, method: &str, path: &str, start_time: Instant) {
        let duration = start_time.elapsed();
        
        info!(
            method = method,
            path = path,
            duration_ms = duration.as_millis(),
            "Request processed"
        );
    }

    pub fn log_error(&self, method: &str, path: &str, error: &str) {
        warn!(
            method = method,
            path = path,
            error = error,
            "Request failed"
        );
    }
}