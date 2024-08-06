#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::str::FromStr;

use alloy::primitives::FixedBytes;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::account_address::AccountAddress;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::Client;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::types::LocalAccount;
use async_trait::async_trait;
use c_kzg::{Blob, KzgCommitment, KzgProof, KzgSettings, BYTES_PER_BLOB};

use da_client_interface::{DaClient, DaVerificationStatus};
use utils::env_utils::get_env_var_or_panic;

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

#[async_trait]
impl DaClient for AptosDaClient {
    async fn publish_state_diff(&self, state_diff: Vec<Vec<u8>>, _to: &[u8; 32]) -> color_eyre::Result<String> {
        // Create blobs, commitments, proofs from state_diff and trusted setup and transfer to "MoveValue".
        let data = prepare_blob(&state_diff, &self.trusted_setup).await?;
        let loop_cycle = get_env_var_or_panic("LOOP_CYCLE").parse::<usize>()?;

        // TODO: It’s better to use .unzip() for cleaner code.
        let (blobs, commitments, proofs) = data
            .into_iter()
            .map(|(blob, commitment, proof)| {
                (
                    // Split blobs into "loop_cycle" parts.
                    blob.to_vec()
                        .chunks(BYTES_PER_BLOB / loop_cycle)
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

        for i in 0..loop_cycle {
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

        // Submit transaction.
        let pending_transactions = txs
            .into_iter()
            .map(|tx| {
                let client = self.client.clone();
                tokio::spawn(async move {
                    
                    client.submit(&tx).await.unwrap().into_inner()
                })
            })
            .collect::<Vec<_>>();

        let mut results = Vec::with_capacity(pending_transactions.len());
        for handle in pending_transactions {
            results.push(handle.await.unwrap());
        }

        // Wait for transaction.
        let results = results
            .into_iter()
            .map(|pending_tx| {
                let client = self.client.clone();
                tokio::spawn(async move {
                    let transaction = client.wait_for_transaction(&pending_tx).await.unwrap().into_inner();
                    let transaction_info = transaction.transaction_info().unwrap();
                    transaction_info.hash.to_string()
                })
            })
            .collect::<Vec<_>>();

        // Handle "wait for transaction" threads and combine the transaction hash.
        let mut hashes_combined: String = "".to_string();
        for handle in results {
            let hash = handle.await.unwrap();
            hashes_combined.push_str(&hash);
        }

        Ok(hashes_combined)
    }

    async fn verify_inclusion(&self, external_id: &str) -> color_eyre::Result<DaVerificationStatus> {
        let client = &self.client;
        let txn = client.get_transaction_by_hash(HashValue::from_str(external_id).unwrap()).await?;
        let response = txn.into_inner();
        match response.success() {
            true => Ok(DaVerificationStatus::Verified),
            false => match response.is_pending() {
                true => Ok(DaVerificationStatus::Pending),
                false => Ok(DaVerificationStatus::Rejected("Failed".parse()?)),
            },
        }
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
    use alloy::hex;
    use aptos_sdk::move_types::u256;
    use aptos_sdk::transaction_builder::TransactionBuilder;
    use da_client_interface::DaConfig;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::AptosDaConfig;

    use super::*;

    const INIT_CONTRACT_STATE: &'static str = "initialize_contract_state";

    #[tokio::test]
    async fn test_submit_blob() {
        let da_config = AptosDaConfig::new_from_env();
        let da_client = AptosDaConfig::build_client(&da_config).await;

        let data = vec![hex::decode(include_str!("../test_utils/hex_block_630872.txt")).unwrap()];
        da_client
            .publish_state_diff(data, &u256::U256::from(0u128).to_le_bytes())
            .await
            .expect("Failed to submit blob!");
    }

    #[tokio::test]
    async fn init_state() {
        let da_config = AptosDaConfig::new_from_env();
        let da_client = AptosDaConfig::build_client(&da_config).await;

        let client = da_client.client;
        let account = da_client.account;
        let chain_id = da_client.chain_id;
        let module_address = da_client.module_address;

        let sequence_number = client.get_account(account.address()).await.unwrap().into_inner().sequence_number;
        account.set_sequence_number(sequence_number);

        let sequencer_number = account.increment_sequence_number();

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
        .sender(account.address())
        .sequence_number(sequencer_number)
        .max_gas_amount(10000)
        .gas_unit_price(100)
        .build();

        let signed_txn = account.sign_transaction(tx_builder);
        let tx = client.submit_and_wait(&signed_txn).await.expect("Failed to submit transfer transaction").into_inner();

        println!("{:?}", tx);

        assert!(tx.success(), "Transaction Failed");
    }
}
