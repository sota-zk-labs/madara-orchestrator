#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::time::{SystemTime, UNIX_EPOCH};
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::transaction_argument::TransactionArgument::U256;
use aptos_sdk::move_types::value::serialize_values;
use aptos_sdk::rest_client::aptos_api_types::MoveValue;
use aptos_sdk::rest_client::Client;
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::{AccountKey, LocalAccount};
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::EntryABI::EntryFunction;
use aptos_sdk::types::transaction::TransactionPayload;
use async_trait::async_trait;
use color_eyre::eyre;
use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};
use crate::config::AptosSettlementConfig;


pub mod config;
pub struct AptosSettlementClient {
    pub client: Client,
    pub account: LocalAccount,
}

impl From<AptosSettlementConfig> for AptosSettlementClient {
    fn from(config: AptosSettlementConfig) -> Self {
        let client = Client::new(config.node_url.parse().unwrap());
        let private_key = Ed25519PrivateKey::try_from(config.private_key.as_bytes());
        let account_key = AccountKey::from_private_key(private_key.unwrap());
        let account_address = config.account_address.parse().expect("Issue while loading account address");
        let account = LocalAccount::new(account_address, account_key, 0);
        AptosSettlementClient { client, account }
    }
}

#[async_trait]
impl SettlementClient for AptosSettlementClient {
    async fn register_proof(&self, proof: Vec<u8>) -> eyre::Result<String> {
        todo!()
    }

    async fn update_state_calldata(
        &self,
        program_output: Vec<Vec<u8>>,
        onchain_data_hash: Vec<u8>,
        onchain_data_size: usize
    ) -> eyre::Result<String> {
        let client = self.client.clone();
        let account = client.get_account(self.account.address()).await.expect("Failed to get account").into_inner();
        self.account.set_sequence_number(account.sequence_number);

        let program_output_u256: Vec<MoveValue> = program_output.iter()
            .map(|slice| {
                MoveValue::U256(U256::from_big_endian(slice))
            })
            .collect();

        // Convert onchain_data_hash to U256
        let onchain_data_hash_u256 = MoveValue::U256(U256::from_big_endian(&onchain_data_hash));

        // onchain_data_size as U256
        let onchain_data_size_u256 = MoveValue::U256(U256::from(onchain_data_size));

        // Build the transaction payload
        let payload = TransactionPayload::EntryFunction(
            EntryFunction::new(
                ModuleId::new(
                    self.account.address(),
                    Identifier::new("starknet").unwrap(), // Replace with actual module name
                ),
                Identifier::new("update_state").unwrap(), // Replace with actual function name
                vec![], // No type arguments
                serialize_values(vec![
                    &MoveValue::Vector(program_output_u256),
                    &onchain_data_hash_u256,
                    &onchain_data_size_u256,
                ].into_iter()),
            )
        );

        let txn = TransactionBuilder::new(
            payload,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            ChainId::test(),
        )
            .sender(self.account.address())
            .sequence_number(self.account.sequence_number())
            .max_gas_amount(5000)
            .gas_unit_price(100)
            .build();

        let signed_txn = self.account.sign_transaction(txn);

        client.submit(&signed_txn).await?;

        Ok(signed_txn.committed_hash().to_string())
    }

    async fn update_state_blobs(&self, program_output: Vec<Vec<u8>>, kzg_proof: Vec<u8>) -> eyre::Result<String> {
        todo!()
    }

    async fn verify_inclusion(&self, external_id: &str) -> eyre::Result<SettlementVerificationStatus> {
        todo!()
    }

    async fn get_last_settled_block(&self) -> eyre::Result<u64> {
        todo!()
    }
}