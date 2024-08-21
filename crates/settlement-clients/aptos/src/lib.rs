#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::path::{PathBuf};
use std::str::FromStr;
use alloy::eips::eip4844::BYTES_PER_BLOB;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::account_address::AccountAddress;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::aptos_api_types::{EntryFunctionId, ViewRequest};
use aptos_sdk::rest_client::Client;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::types::LocalAccount;
use async_trait::async_trait;
use c_kzg::{Blob, Bytes32, KzgCommitment, KzgProof, KzgSettings};
use color_eyre::eyre;
use color_eyre::eyre::eyre;
use lazy_static::lazy_static;
use mockall::automock;
use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};

use crate::config::AptosSettlementConfig;
use crate::helper::{build_transaction, build_transaction_with_nonce};

pub mod config;
pub mod helper;

pub struct AptosSettlementClient {
    pub client: Client,
    pub account: LocalAccount,
    pub module_address: AccountAddress,
    pub chain_id: ChainId,
}

const STARKNET_VALIDITY: &str = "starknet_validity";
const UPDATE_STATE: &str = "update_state";
const UPDATE_STATE_KZG_DA: &str = "update_state_kzg_da";
const STATE_BLOCK_NUMBER: &str = "state_block_number";

lazy_static! {
    pub static ref CURRENT_PATH: PathBuf = std::env::current_dir().unwrap();
    pub static ref KZG_SETTINGS: KzgSettings =
        // TODO: set more generalized path
        KzgSettings::load_trusted_setup_file(CURRENT_PATH.join("src/trusted_setup.txt").as_path())
            .expect("Error loading trusted setup file");
}

impl AptosSettlementClient {
    /// Build kzg proof for the x_0 point evaluation
    pub fn build_proof(blob_data: Vec<Vec<u8>>, x_0_value: Bytes32) -> color_eyre::Result<KzgProof> {
        // Assuming that there is only one blob in the whole Vec<Vec<u8>> array for now.
        // Later we will add the support for multiple blob in single blob_data vec.
        assert_eq!(blob_data.len(), 1);

        let fixed_size_blob: [u8; BYTES_PER_BLOB] = blob_data[0].as_slice().try_into()?;

        let blob = Blob::new(fixed_size_blob);
        let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, &KZG_SETTINGS)?;
        let (kzg_proof, y_0_value) = KzgProof::compute_kzg_proof(&blob, &x_0_value, &KZG_SETTINGS)?;

        // Verifying the proof for double check
        let eval = KzgProof::verify_kzg_proof(
            &commitment.to_bytes(),
            &x_0_value,
            &y_0_value,
            &kzg_proof.to_bytes(),
            &KZG_SETTINGS,
        )?;

        if !eval { Err(eyre!("ERROR : Assertion failed, not able to verify the proof.")) } else { color_eyre::eyre::Ok(kzg_proof) }
    }
}


impl From<AptosSettlementConfig> for AptosSettlementClient {
    fn from(config: AptosSettlementConfig) -> Self {
        let client = Client::new(config.node_url.parse().unwrap());
        let account = LocalAccount::from_private_key(&config.private_key, 0).unwrap();
        let module_address = config.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&config.chain_id).expect("Invalid chain id");

        AptosSettlementClient { client, account, module_address, chain_id }
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
    ) -> color_eyre::Result<String> {
        let sequencer_number = self.client.get_account(self.account.address()).await?.into_inner().sequence_number;
        self.account.set_sequence_number(sequencer_number);

        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(self.module_address, Identifier::new(STARKNET_VALIDITY).unwrap()),
            Identifier::new(UPDATE_STATE).unwrap(),
            vec![],
            serialize_values(
                vec![
                    &MoveValue::Vector(
                        program_output.iter().map(|s| MoveValue::U256(U256::from_le_bytes(s))).collect::<Vec<_>>(),
                    ),
                    &MoveValue::U256(U256::from_le_bytes(&onchain_data_hash)),
                    &MoveValue::U256(U256::from(onchain_data_size as u128)),
                ]
                    .into_iter(),
            ),
        ));

        let signed_txn = build_transaction(payload, &self.account, self.chain_id);

        let tx = self
            .client
            .submit_and_wait(&signed_txn)
            .await
            .expect("Failed to submit update state transaction")
            .into_inner();
        let transaction_info = tx.transaction_info().unwrap();
        log::info!(
            "update_state_calldata finished: hash={}; gas={}",
            transaction_info.hash.to_string(),
            transaction_info.gas_used
        );

        Ok(transaction_info.hash.to_string())
    }

    async fn update_state_with_blobs(
        &self,
        program_output: Vec<[u8; 32]>,
        state_diff: Vec<Vec<u8>>,
        nonce: u64,
    ) -> color_eyre::Result<String> {
        // x_0_value : program_output[8]
        let kzg_proof = Self::build_proof(
            state_diff,
            Bytes32::from_bytes(program_output[8].as_slice()).expect("Not able to get x_0 point params."),
        )?;

        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(self.account.address(), Identifier::new(STARKNET_VALIDITY).unwrap()),
            Identifier::new(UPDATE_STATE_KZG_DA).unwrap(),
            vec![],
            serialize_values(
                vec![
                    &MoveValue::Vector(
                        program_output.iter().map(|s| MoveValue::U256(U256::from_le_bytes(s))).collect::<Vec<_>>(),
                    ),
                    &MoveValue::vector_u8(kzg_proof.to_vec()),
                ]
                    .into_iter(),
            ),
        ));

        let signed_txn = build_transaction_with_nonce(payload, &self.account, self.chain_id, nonce);

        let tx = self
            .client
            .submit_and_wait(&signed_txn)
            .await
            .expect("Failed to submit update state transaction")
            .into_inner();

        let transaction_info = tx.transaction_info().unwrap();
        log::info!(
            "update_state_blobs finished: hash={}; gas={}",
            transaction_info.hash.to_string(),
            transaction_info.gas_used
        );

        Ok(transaction_info.hash.to_string())
    }

    async fn verify_tx_inclusion(&self, tx_hash: &str) -> eyre::Result<SettlementVerificationStatus> {
        let client = self.client.clone();

        let hash = HashValue::from_str(tx_hash.strip_prefix("0x").unwrap())?;
        let txn = client.get_transaction_by_hash(hash).await?;

        let response = txn.into_inner();
        match response.success() {
            true => Ok(SettlementVerificationStatus::Verified),
            false => Ok(SettlementVerificationStatus::Rejected(format!("Transaction {} have been rejected.", tx_hash))),
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
            function: EntryFunctionId::from_str(
                format!(
                    "{}::{}::{}",
                    self.account.address().to_string().as_str(),
                    STARKNET_VALIDITY,
                    STATE_BLOCK_NUMBER
                )
                    .as_str(),
            )
                .expect("Invalid function name"),
        };
        let response = client.view(&request, None).await?.into_inner();

        let block_number = response.first().unwrap().as_str().unwrap();
        Ok(block_number.parse::<u64>()?)
    }

    async fn get_nonce(&self) -> color_eyre::Result<u64> {
        Ok(self
            .client
            .get_account(self.account.address())
            .await?
            .into_inner()
            .sequence_number)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use aptos_sdk::crypto::ValidCryptoMaterialStringExt;
    use aptos_sdk::move_types::identifier::Identifier;
    use aptos_sdk::move_types::language_storage::ModuleId;
    use aptos_sdk::move_types::u256;
    use aptos_sdk::move_types::value::{serialize_values, MoveValue};
    use aptos_sdk::types::chain_id::NamedChain::TESTING;
    use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
    use aptos_testcontainer::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};
    use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};
    use test_log::test;

    use super::*;
    use crate::config::AptosSettlementConfig;
    use crate::helper::build_transaction;
    use crate::{AptosSettlementClient, STARKNET_VALIDITY};

    const REGISTER_FACT: &str = "register_fact";
    const FACT_REGISTRY: &str = "fact_registry";
    const INIT_CONTRACT_STATE: &str = "initialize_contract_state";

    async fn aptos_init_state(settlement_client: &AptosSettlementClient) {
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(settlement_client.account.address(), Identifier::new(STARKNET_VALIDITY).unwrap()),
            Identifier::new(INIT_CONTRACT_STATE).unwrap(),
            vec![],
            serialize_values(
                vec![
                    &MoveValue::U256(u256::U256::from(0u128)),
                    &MoveValue::Address(AccountAddress::ZERO),
                    &MoveValue::U256(u256::U256::from(0u128)),
                    &MoveValue::U256(u256::U256::from(0u128)),
                    &MoveValue::U256(u256::U256::from(0u128)),
                    &MoveValue::U256(u256::U256::from(0u128)),
                ]
                    .into_iter(),
            ),
        ));
        let tx = build_transaction(payload, &settlement_client.account, settlement_client.chain_id);
        let tx = settlement_client.client.submit_and_wait(&tx).await.expect("Failed to init state!").into_inner();
        let transaction_info = tx.transaction_info().unwrap();
        log::info!(
            "update_state_blobs finished: hash={}; gas={}",
            transaction_info.hash.to_string(),
            transaction_info.gas_used
        );
    }

    async fn aptos_fact_registry(settlement_client: &AptosSettlementClient, fact: &str) {
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(settlement_client.account.address(), Identifier::new(FACT_REGISTRY).unwrap()),
            Identifier::new(REGISTER_FACT).unwrap(),
            vec![],
            serialize_values(vec![&MoveValue::vector_u8(hex::decode(fact).unwrap())].into_iter()),
        ));
        let tx = build_transaction(payload, &settlement_client.account, settlement_client.chain_id);
        let tx = settlement_client.client.submit_and_wait(&tx).await.expect("Failed to registry fact!").into_inner();
        let transaction_info = tx.transaction_info().unwrap();
        log::info!(
            "update_state_blobs finished: hash={}; gas={}",
            transaction_info.hash.to_string(),
            transaction_info.gas_used
        );
    }

    #[test(tokio::test)]
    async fn test_update_state_calldata() -> anyhow::Result<()> {
        run(1, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await.unwrap();
                let node_url = aptos_container.get_node_url().await.unwrap();

                let module_account_private_key = accounts.first().unwrap();
                let module_account = LocalAccount::from_private_key(module_account_private_key, 0).unwrap();

                let config = AptosSettlementConfig {
                    node_url,
                    private_key: module_account_private_key.to_string(),
                    module_address: module_account.address().to_string(),
                    chain_id: TESTING.id().to_string(),
                };
                let settlement_client = AptosSettlementClient::from(config);

                let mut named_address = HashMap::new();
                named_address.insert("starknet_addr".to_string(), module_account.address().to_string());
                aptos_container
                    .upload_contract(
                        "../../../ionia",
                        &module_account.private_key().to_encoded_string().unwrap(),
                        &named_address,
                        false,
                    )
                    .await
                    .unwrap();

                let sequence_number = settlement_client
                    .client
                    .get_account(settlement_client.account.address())
                    .await?
                    .into_inner()
                    .sequence_number;
                settlement_client.account.set_sequence_number(sequence_number);

                aptos_init_state(&settlement_client).await;

                aptos_fact_registry(
                    &settlement_client,
                    "38a811b0f756a978eda5dd75bdaecc4942f7eba409805c88edf1442dcaea2cdc",
                )
                    .await;

                let program_output: Vec<[u8; 32]> = vec![
                    u256::U256::from(0u128).to_le_bytes(), // Global root
                    u256::U256::from(0u128).to_le_bytes(), // Message offset
                    u256::U256::from(1u128).to_le_bytes(), // Block number offset
                    u256::U256::from(1u128).to_le_bytes(), // Block hash offset
                    u256::U256::from(0u128).to_le_bytes(), // Config hash offset
                    u256::U256::from(0u128).to_le_bytes(),
                    u256::U256::from(0u128).to_le_bytes(),
                    u256::U256::from(0u128).to_le_bytes(),
                ];
                let onchain_data_hash = u256::U256::from(1u128).to_le_bytes();
                let onchain_data_size = 1usize;

                let result = settlement_client
                    .update_state_calldata(program_output, onchain_data_hash, onchain_data_size)
                    .await
                    .expect("Failed to submit blob!");
                log::info!("result = {:#?}", result);

                let verify_inclusion = settlement_client.verify_tx_inclusion(result.as_str()).await.unwrap();
                log::info!("verify_inclusion = {:#?}", verify_inclusion);
                assert_eq!(verify_inclusion, SettlementVerificationStatus::Verified);

                let block_number = settlement_client.get_last_settled_block().await.unwrap();
                log::info!("block_number = {:#?}", block_number);
                Ok(())
            })
        })
            .await
    }
}
