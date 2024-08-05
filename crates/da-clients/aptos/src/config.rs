use std::path::Path;
use std::str::FromStr;

use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::crypto::ValidCryptoMaterialStringExt;
use aptos_sdk::rest_client::Client;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::{AccountKey, LocalAccount};
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
    pub account_address: String,
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
        let account_address = get_env_var_or_panic("APTOS_ACCOUNT_ADDRESS");
        let module_address = get_env_var_or_panic("APTOS_MODULE_ADDRESS");
        let chain_id = get_env_var_or_panic("CHAIN_ID");
        let trusted_setup = get_env_var_or_panic("TRUSTED_SETUP");

        Self { chain_id, node_url, private_key, account_address, module_address, trusted_setup }
    }

    async fn build_client(&self) -> AptosDaClient {
        let client = Client::new(self.node_url.parse().unwrap());
        let private_key =
            Ed25519PrivateKey::from_encoded_string(&self.private_key).expect("Failed to parse private key");
        let account_key = AccountKey::from(private_key);
        let account_address = self.account_address.parse().expect("Invalid account address");
        let account = LocalAccount::new(account_address, account_key, 0);
        let module_address = self.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&self.chain_id).expect("Invalid chain id");
        let trusted_setup =
            KzgSettings::load_trusted_setup_file(Path::new(&self.trusted_setup)).expect("Failed to load trusted setup");

        AptosDaClient { client, account, module_address, chain_id, trusted_setup }
    }
}
