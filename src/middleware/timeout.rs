use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    pub request_timeout: Duration,
    pub connection_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
        }
    }
}

pub struct TimeoutMiddleware {
    config: TimeoutConfig,
}

impl TimeoutMiddleware {
    pub fn new(config: TimeoutConfig) -> Self {
        Self { config }
    }

    pub fn request_timeout(&self) -> Duration {
        self.config.request_timeout
    }

    pub fn connection_timeout(&self) -> Duration {
        self.config.connection_timeout
    }
}