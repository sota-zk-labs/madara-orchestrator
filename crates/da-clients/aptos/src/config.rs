use std::path::Path;
use std::str::FromStr;

use aptos_sdk::rest_client::Client;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::LocalAccount;
use c_kzg::KzgSettings;
use utils::settings::Settings;

use crate::AptosDaClient;

#[derive(Clone, Debug)]
pub struct AptosDaConfig {
    pub node_url: String,
    pub private_key: String,
    pub module_address: String,
    pub chain_id: String,
    pub trusted_setup: String,
}

impl AptosDaConfig {
    pub fn new_with_settings(settings: &impl Settings) -> Self {
        Self {
            node_url: settings.get_settings_or_panic("APTOS_NODE_URL"),
            private_key: settings.get_settings_or_panic("APTOS_PRIVATE_KEY"),
            module_address: settings.get_settings_or_panic("APTOS_MODULE_ADDRESS"),
            chain_id: settings.get_settings_or_panic("CHAIN_ID"),
            trusted_setup: settings.get_settings_or_panic("APTOS_CRS_PATH"),
        }
    }

    pub async fn build_client(&self) -> AptosDaClient {
        let client = Client::new(self.node_url.parse().unwrap());
        let account = LocalAccount::from_private_key(&self.private_key, 0).unwrap();
        let module_address = self.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&self.chain_id).expect("Invalid chain id");
        let trusted_setup =
            KzgSettings::load_trusted_setup_file(Path::new(&self.trusted_setup)).expect("Failed to load trusted setup");

        AptosDaClient { client, account, module_address, chain_id, trusted_setup }
    }
}
