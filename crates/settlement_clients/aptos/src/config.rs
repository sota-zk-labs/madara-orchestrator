use settlement_client_interface::SettlementConfig;
use utils::env_utils::get_env_var_or_panic;

#[derive(Clone, Debug)]
pub struct AptosSettlementConfig {
    
}

impl SettlementConfig for AptosSettlementConfig {
    fn new_from_env() -> Self {
        todo!()
    }
}