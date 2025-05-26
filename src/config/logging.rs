use serde::{Deserialize, Serialize};

// TODO: implement this into the code, this is currently just a placeholder for the future logging configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LoggingConfig {
    log_level: String,
}
