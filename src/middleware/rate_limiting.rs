use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
        }
    }
}

pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    counters: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            counters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_allowed(&self, client_id: &str) -> bool {
        let mut counters = self.counters.lock().unwrap();
        let now = Instant::now();
        
        match counters.get_mut(client_id) {
            Some((count, last_reset)) => {
                if now.duration_since(*last_reset) >= self.config.window_duration {
                    *count = 1;
                    *last_reset = now;
                    true
                } else if *count < self.config.requests_per_window {
                    *count += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                counters.insert(client_id.to_string(), (1, now));
                true
            }
        }
    }
}