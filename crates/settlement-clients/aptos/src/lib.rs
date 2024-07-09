#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::aptos_api_types::{EntryFunctionId, ViewRequest};
use aptos_sdk::rest_client::Client;
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::EntryFunction;
use aptos_sdk::types::transaction::TransactionPayload;
use aptos_sdk::types::{AccountKey, LocalAccount};
use async_trait::async_trait;
use color_eyre::eyre;
use mockall::automock;

use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};

use crate::config::AptosSettlementConfig;
use crate::conversion::{slice_from_u8_to_string, slice_from_u8_to_u256, slice_from_vec_u8_to_u256};

pub mod config;
pub mod conversion;

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

#[automock]
#[async_trait]
impl SettlementClient for AptosSettlementClient {
    #[allow(unused)]
    async fn register_proof(&self, proof: [u8; 32]) -> eyre::Result<String> {
        unimplemented!("hee-hee")
    }

    async fn update_state_calldata(
        &self,
        program_output: Vec<[u8; 32]>,
        onchain_data_hash: [u8; 32],
        onchain_data_size: usize,
    ) -> eyre::Result<String> {
        let client = self.client.clone();
        let account = client.get_account(self.account.address()).await.expect("Failed to get account").into_inner();
        self.account.set_sequence_number(account.sequence_number);

        // Build the transaction payload
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(self.account.address(), Identifier::new("starknet").unwrap()),
            Identifier::new("update_state").unwrap(),
            vec![], // No type arguments
            serialize_values(
                vec![
                    &MoveValue::Vector(slice_from_vec_u8_to_u256(&program_output)),
                    &slice_from_u8_to_u256(&onchain_data_hash),
                    &MoveValue::U256(U256::from_str(onchain_data_size.to_string().as_str()).unwrap()),
                ]
                .into_iter(),
            ),
        ));

        let txn = TransactionBuilder::new(
            payload,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60,
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

    async fn update_state_blobs(&self, program_output: Vec<[u8; 32]>, kzg_proof: [u8; 48]) -> eyre::Result<String> {
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(self.account.address(), Identifier::new("starknet").unwrap()),
            Identifier::new("update_state_kzg_da").unwrap(),
            vec![],
            serialize_values(
                vec![
                    &MoveValue::Vector(slice_from_vec_u8_to_u256(&program_output)),
                    // This variable has a strange type of data '[u8; 48]' for Move and Aptos, so I
                    // convert it into an U256 variable.
                    &MoveValue::U256(U256::from_str(unsafe { slice_from_u8_to_string(&kzg_proof) }.as_str()).unwrap()),
                ]
                .into_iter(),
            ),
        ));

        let txn = TransactionBuilder::new(
            payload,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60,
            ChainId::test(),
        )
        .sender(self.account.address())
        .sequence_number(self.account.sequence_number())
        .max_gas_amount(5000)
        .gas_unit_price(100)
        .build();

        let signed_txn = self.account.sign_transaction(txn);

        self.client.submit(&signed_txn).await?;

        Ok(signed_txn.committed_hash().to_string())
    }

    async fn verify_tx_inclusion(&self, tx_hash: &str) -> eyre::Result<SettlementVerificationStatus> {
        let client = &self.client;
        let txn = client.get_transaction_by_hash(HashValue::from_str(tx_hash).unwrap()).await?;
        let response = txn.into_inner();
        match response.success() {
            true => Ok(SettlementVerificationStatus::Verified),
            false => match response.is_pending() {
                true => Ok(SettlementVerificationStatus::Pending),
                false => {
                    Ok(SettlementVerificationStatus::Rejected(format!("Transaction {} have been rejected.", tx_hash)))
                }
            },
        }
    }

    #[allow(unused)]
    async fn wait_for_tx_finality(&self, tx_hash: &str) -> color_eyre::Result<()> {
        unimplemented!("hee-hee")
    }

    async fn get_last_settled_block(&self) -> eyre::Result<u64> {
        let client = &self.client;
        let request = ViewRequest {
            type_arguments: vec![],
            arguments: vec![],
            function: EntryFunctionId::from_str("starknet::state_block_number").unwrap(),
        };
        let response = client.view(&request, None).await?.into_inner();
        let block_number = response[0].as_u64().unwrap();
        Ok(block_number)
    }
}
