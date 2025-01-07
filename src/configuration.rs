use std::path::Path;

use serde_aux::field_attributes::deserialize_number_from_string;

#[derive(serde::Deserialize, Debug)]
pub struct Settings {
    pub interfaces: Vec<String>,
    pub log_level: String,
    pub blocking: BlockingSettings,
}

#[derive(serde::Deserialize, Debug)]
pub struct BlockingSettings {
    // Maximum allowed requests within the burst period
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub burst_limit: u16,

    // Burst period in seconds
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub burst_period_secs: u16,

    // Temporary ban duration in seconds for the first offense
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub initial_ban_duration: u16,

    // Multiplier for increating ban duration after repeated offenses
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub ban_multiplier: u16,

    // Maximum duration for temporary ban in seconds
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub max_temp_ban_duration: u16,

    // Number of repeated offenses after which the IP is banned permanently
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub permanent_ban_threshold: u16,
}

pub fn get_configuration(config_dir: &Path) -> Result<Settings, config::ConfigError> {
    let settings = config::Config::builder()
        .add_source(config::File::from(config_dir.join("config.toml")))
        .build()?;

    settings.try_deserialize::<Settings>()
}
