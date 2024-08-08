use std::path::Path;
use std::str::FromStr;

use aptos_sdk::rest_client::Client;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::LocalAccount;
use async_trait::async_trait;
use c_kzg::KzgSettings;
use dotenvy::dotenv;

use da_client_interface::DaConfig;
use utils::env_utils::get_env_var_or_panic;

use crate::AptosDaClient;

#[derive(Clone, Debug)]
pub struct AptosDaConfig {
    pub node_url: String,
    pub private_key: String,
    pub module_address: String,
    pub chain_id: String,
    pub trusted_setup: String,
}

#[async_trait]
impl DaConfig<AptosDaClient> for AptosDaConfig {
    fn new_from_env() -> Self {
        dotenv().expect("Failed to load .env file");
        let node_url = get_env_var_or_panic("APTOS_NODE_URL");
        let private_key = get_env_var_or_panic("APTOS_PRIVATE_KEY");
        let module_address = get_env_var_or_panic("APTOS_MODULE_ADDRESS");
        let chain_id = get_env_var_or_panic("APTOS_CHAIN_ID");
        let trusted_setup = get_env_var_or_panic("APTOS_CRS_PATH");

        Self { chain_id, node_url, private_key, module_address, trusted_setup }
    }

    async fn build_client(&self) -> AptosDaClient {
        let client = Client::new(self.node_url.parse().unwrap());
        let account = LocalAccount::from_private_key(&self.private_key, 0).unwrap();
        let module_address = self.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&self.chain_id).expect("Invalid chain id");
        let trusted_setup =
            KzgSettings::load_trusted_setup_file(Path::new(&self.trusted_setup)).expect("Failed to load trusted setup");

        AptosDaClient { client, account, module_address, chain_id, trusted_setup }
    }
}
