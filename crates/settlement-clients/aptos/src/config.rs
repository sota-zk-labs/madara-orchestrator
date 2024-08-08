use dotenvy::dotenv;
use settlement_client_interface::SettlementConfig;
use utils::env_utils::get_env_var_or_panic;

pub struct AptosSettlementConfig {
    pub node_url: String,
    pub private_key: String,
    pub account_address: String,
    pub module_address: String,
    pub chain_id: String,
}

impl SettlementConfig for AptosSettlementConfig {
    fn new_from_env() -> Self {
        dotenv().expect("Failed to load .env file");
        let node_url = get_env_var_or_panic("APTOS_NODE_URL");
        let private_key = get_env_var_or_panic("APTOS_PRIVATE_KEY");
        let account_address = get_env_var_or_panic("APTOS_ACCOUNT_ADDRESS");
        let module_address = get_env_var_or_panic("APTOS_MODULE_ADDRESS");
        let chain_id = get_env_var_or_panic("CHAIN_ID");
        AptosSettlementConfig { chain_id, node_url, private_key, account_address, module_address }
    }
}
