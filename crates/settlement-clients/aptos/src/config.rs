use settlement_client_interface::SettlementConfig;
use utils::env_utils::get_env_var_or_panic;

pub struct AptosSettlementConfig {
    pub node_url: String,
    pub private_key: String,
    pub account_address: String,
}

impl SettlementConfig for AptosSettlementConfig {
    fn new_from_env() -> Self {
        Self {
            node_url: get_env_var_or_panic("APTOS_NODE_URL"),
            private_key: get_env_var_or_panic("PRIVATE_KEY"),
            account_address: get_env_var_or_panic("ADDRESS"),
        }
    }
}
