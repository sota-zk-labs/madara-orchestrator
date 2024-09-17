use settlement_client_interface::SettlementConfig;
use utils::settings::Settings;

pub struct AptosSettlementConfig {
    pub node_url: String,
    pub private_key: String,
    pub module_address: String,
    pub chain_id: String,
}

impl SettlementConfig for AptosSettlementConfig {
    fn new_with_settings(settings: &impl Settings) -> Self {
        Self {
            node_url: settings.get_settings_or_panic("APTOS_NODE_URL"),
            private_key: settings.get_settings_or_panic("APTOS_PRIVATE_KEY"),
            module_address: settings.get_settings_or_panic("APTOS_MODULE_ADDRESS"),
            chain_id: settings.get_settings_or_panic("CHAIN_ID"),
        }
    }
}
