#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::str::FromStr;

use alloy::primitives::FixedBytes;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::account_address::AccountAddress;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::value::{MoveValue, serialize_values};
use aptos_sdk::rest_client::{Client, PendingTransaction};
use aptos_sdk::rest_client::error::RestError;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::LocalAccount;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use async_trait::async_trait;
use c_kzg::{Blob, BYTES_PER_BLOB, KzgCommitment, KzgProof, KzgSettings};

use da_client_interface::{DaClient, DaVerificationStatus};

use crate::helper::build_transaction;

pub mod config;
mod helper;

pub struct AptosDaClient {
    pub client: Client,
    pub account: LocalAccount,
    pub module_address: AccountAddress,
    pub chain_id: ChainId,
    pub trusted_setup: KzgSettings,
}

const STARKNET_VALIDITY: &str = "starknet_validity";
const BLOB_SUBMISSION: &str = "blob_submission";
const MAX_BLOB_PART_SIZE: usize = 32768;

#[async_trait]
impl DaClient for AptosDaClient {
    async fn publish_state_diff(&self, state_diff: Vec<Vec<u8>>, _to: &[u8; 32]) -> color_eyre::Result<String> {
        let data = prepare_blob(&state_diff, &self.trusted_setup).await?;

        let (blobs, commitments, proofs) = data
            .into_iter()
            .map(|(blob, commitment, proof)| {
                (
                    // Split blobs into "loop_cycle" parts
                    blob.to_vec()
                        .chunks(MAX_BLOB_PART_SIZE)
                        .map(|part| vec![MoveValue::vector_u8(part.to_vec())])
                        .collect::<Vec<_>>(),
                    MoveValue::vector_u8(commitment.to_vec()),
                    MoveValue::vector_u8(proof.to_vec()),
                )
            })
            .fold((vec![], vec![], vec![]), |(mut blobs, mut commitments, mut proofs), (blob, commitment, proof)| {
                blobs.push(blob);
                commitments.push(commitment);
                proofs.push(proof);
                (blobs, commitments, proofs)
            });

        // Build and sign transaction
        let sequence_number = self.client.get_account(self.account.address()).await?.into_inner().sequence_number;
        self.account.set_sequence_number(sequence_number);
        let mut txs = vec![];

        for i in 0..BYTES_PER_BLOB / MAX_BLOB_PART_SIZE {
            let payload = TransactionPayload::EntryFunction(EntryFunction::new(
                ModuleId::new(self.account.address(), Identifier::new(STARKNET_VALIDITY).unwrap()),
                Identifier::new(BLOB_SUBMISSION).unwrap(),
                vec![],
                serialize_values(vec![
                    &MoveValue::Vector(blobs.first().unwrap().get(i).unwrap().to_vec()),
                    &MoveValue::Vector(commitments.clone()),
                    &MoveValue::Vector(proofs.clone()),
                ]),
            ));
            let tx = build_transaction(payload, &self.account, self.chain_id);
            txs.push(tx);
        }

        // Submit transaction
        let pending_transactions = txs
            .into_iter()
            .map(|tx| {
                let client = self.client.clone();
                tokio::spawn(async move { Ok::<PendingTransaction, RestError>(client.submit(&tx).await?.into_inner()) })
            })
            .collect::<Vec<_>>();

        let mut results = Vec::with_capacity(pending_transactions.len());
        for handle in pending_transactions {
            results.push(handle.await.unwrap());
        }

        // Wait for transaction
        let results = results
            .into_iter()
            .map(|pending_tx| {
                let client = self.client.clone();
                tokio::spawn(async move {
                    let pending_tx = pending_tx?;
                    let transaction = client.wait_for_transaction(&pending_tx).await.unwrap().into_inner();
                    let transaction_info = transaction.transaction_info().unwrap();
                    Ok::<String, RestError>(transaction_info.hash.to_string())
                })
            })
            .collect::<Vec<_>>();

        // Handle "wait for transaction" threads and combine the transaction hash
        let mut hashes_combined: String = "".to_string();
        for handle in results {
            let hash: String = handle.await?.unwrap();
            hashes_combined.push_str(&hash);
        }

        Ok(hashes_combined)
    }

    async fn verify_inclusion(&self, external_id: &str) -> color_eyre::Result<DaVerificationStatus> {
        let client = &self.client;

        let hash_split = external_id.split("0x").filter(|&s| !s.is_empty()).collect::<Vec<_>>();
        let failed_hashes: Vec<&str> = Vec::new();

        for hash_ptr in hash_split {
            let hash = HashValue::from_str(hash_ptr)?;
            match client.get_transaction_by_hash(hash).await {
                Ok(tx) => {
                    if !tx.into_inner().success() {
                        return Ok(DaVerificationStatus::Rejected(format!("Transaction {:#?} failed", failed_hashes)));
                    }
                }
                Err(e) => {
                    // Handle the case where the transaction retrieval fails
                    return Err(color_eyre::Report::new(e));
                }
            }
        }
        Ok(DaVerificationStatus::Verified)
    }

    async fn max_blob_per_txn(&self) -> u64 {
        // This value is set to 1 due to the MAX_TRANSACTION_SIZE
        1
    }

    async fn max_bytes_per_blob(&self) -> u64 {
        // 4096 * 32
        131072
    }
}

async fn prepare_blob(
    state_diff: &[Vec<u8>],
    trusted_setup: &KzgSettings,
) -> color_eyre::Result<Vec<(FixedBytes<131072>, FixedBytes<48>, FixedBytes<48>)>> {
    let mut result = vec![];

    for blob_data in state_diff {
        let mut fixed_size_blob = [0; BYTES_PER_BLOB];
        fixed_size_blob.copy_from_slice(blob_data.as_slice());

        let blob = Blob::new(fixed_size_blob);

        let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, trusted_setup)?;
        let proof = KzgProof::compute_blob_kzg_proof(&blob, &commitment.to_bytes(), trusted_setup)?;

        result.push((
            FixedBytes::new(fixed_size_blob),
            FixedBytes::new(commitment.to_bytes().into_inner()),
            FixedBytes::new(proof.to_bytes().into_inner()),
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy::hex;
    use aptos_sdk::move_types::u256;
    use aptos_sdk::transaction_builder::TransactionBuilder;
    use aptos_testcontainer::aptos_container::AptosContainer;
    use lazy_static::lazy_static;
    use tokio::sync::Mutex;

    use da_client_interface::DaConfig;

    use crate::config::AptosDaConfig;

    use super::*;

    const INIT_CONTRACT_STATE: &'static str = "initialize_contract_state";

    lazy_static! {
        static ref APTOS_CONTAINER: Arc<Mutex<Option<AptosContainer>>> = Arc::new(Mutex::new(None));
        static ref MODULE_ACCOUNT: LocalAccount =
            LocalAccount::from_private_key("0x73791ce34b2414d4afcb87561b0c442e48a3260f1c96de31da80f7cf2eec8113", 0).unwrap();
        static ref SENDER_ACCOUNT: LocalAccount =
           LocalAccount::from_private_key("0x73791ce34b2414d4afcb87561b0c442e48a3260f1c96de31da80f7cf2eec8113", 0).unwrap();
    }

    async fn init_aptos() {
        let mut container = APTOS_CONTAINER.lock().await;

        if container.is_none() {
            let aptos_container = AptosContainer::init().await.unwrap();

            aptos_container.faucet(&MODULE_ACCOUNT).await.unwrap();
            aptos_container.faucet(&SENDER_ACCOUNT).await.unwrap();

            let mut named_addresses = HashMap::new();
            named_addresses.insert("starknet_addr".to_string(), MODULE_ACCOUNT.address().to_string());

            aptos_container.upload_contract("../../../../ionia", &MODULE_ACCOUNT, &named_addresses).await.unwrap();

            *container = Some(aptos_container);
        };
    }

    async fn init_aptos_client() -> AptosDaClient {
        init_aptos().await;

        let aptos_container = APTOS_CONTAINER.lock().await;
        let aptos_container = aptos_container.as_ref().unwrap();

        let da_config = AptosDaConfig {
            node_url: aptos_container.get_node_url().await.unwrap(),
            private_key: SENDER_ACCOUNT.private_key().to_string(),
            module_address: MODULE_ACCOUNT.address().to_string(),
            chain_id: "4".to_string(),
            trusted_setup: "./trusted_setup.txt".to_string(),
        };

        let da_client = AptosDaConfig::build_client(&da_config).await;
        da_client
    }

    #[tokio::test]
    async fn test_aptos_da_client() {
        let da_client = init_aptos_client().await;

        let chain_id = da_client.chain_id.clone();
        let module_address = da_client.module_address.clone();

        let sequence_number =
            da_client.client.get_account(da_client.account.address()).await.unwrap().into_inner().sequence_number;
        da_client.account.set_sequence_number(sequence_number);

        let sequencer_number = da_client.account.increment_sequence_number();

        let tx_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(EntryFunction::new(
                ModuleId::new(module_address, Identifier::new(STARKNET_VALIDITY).unwrap()),
                Identifier::new(INIT_CONTRACT_STATE).unwrap(),
                vec![],
                serialize_values(
                    vec![
                        &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                        &MoveValue::Address(AccountAddress::ZERO),
                        &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                        &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                        &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                        &MoveValue::U256(u256::U256::from_str_radix("0", 10).unwrap()),
                    ]
                        .into_iter(),
                ),
            )),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60,
            chain_id,
        )
            .sender(da_client.account.address())
            .sequence_number(sequencer_number)
            .max_gas_amount(10000)
            .gas_unit_price(100)
            .build();

        let signed_txn = da_client.account.sign_transaction(tx_builder);
        let tx = da_client
            .client
            .submit_and_wait(&signed_txn)
            .await
            .expect("Failed to submit transfer transaction")
            .into_inner();

        assert!(tx.success(), "Transaction Failed");

        let data = vec![hex::decode(include_str!("../test_utils/hex_block_630872.txt")).unwrap()];
        let result = da_client
            .publish_state_diff(data, &u256::U256::from(0u128).to_le_bytes())
            .await
            .expect("Failed to submit blob!");
        eprintln!("result = {:#?}", result);

        let verify_inclusion = da_client.verify_inclusion(result.as_str()).await.unwrap();
        eprintln!("verify_inclusion = {:#?}", verify_inclusion);
    }
}