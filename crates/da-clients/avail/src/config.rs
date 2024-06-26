use da_client_interface::DaConfig;
use serde::Deserialize;
use utils::env_utils::get_env_var_or_panic;

#[derive(Clone, PartialEq, Deserialize, Debug)]
pub struct AvailConfig {
    pub provider: String,
    pub app_id: u32,
    pub seed: String,
}

impl DaConfig for AvailConfig {
    fn new_from_env() -> Self {
        Self {
            provider: get_env_var_or_panic("AVAIL_PROVIDER"),
            app_id: get_env_var_or_panic("AVAIL_APP_ID").parse().unwrap(),
            seed: get_env_var_or_panic("SEED"),
        }
    }
}
