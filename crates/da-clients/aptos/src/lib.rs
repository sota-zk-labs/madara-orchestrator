#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::path::Path;
use std::str::FromStr;

use alloy::primitives::private::serde::{Deserialize, Serialize};
use alloy::primitives::FixedBytes;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::account_address::AccountAddress;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::error::RestError;
use aptos_sdk::rest_client::{Client, PendingTransaction, Transaction};
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::types::LocalAccount;
use async_trait::async_trait;
use c_kzg::{Blob, KzgCommitment, KzgProof, KzgSettings, BYTES_PER_BLOB};
use da_client_interface::{DaClient, DaVerificationStatus};

use crate::helper::build_transaction;

pub mod helper;

const STARKNET_VALIDITY: &str = "starknet_validity";
const BLOB_SUBMISSION: &str = "blob_submission";
const MAX_BLOB_PART_SIZE: usize = 32768;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AptosDaValidatedArgs {
    pub node_url: String,
    pub private_key: String,
    pub module_address: String,
    pub chain_id: String,
    pub trusted_setup: String,
}

pub struct AptosDaClient {
    pub client: Client,
    pub account: LocalAccount,
    pub module_address: AccountAddress,
    pub chain_id: ChainId,
    pub trusted_setup: KzgSettings,
}

impl AptosDaClient {
    pub async fn new_with_args(da_params: &AptosDaValidatedArgs) -> Self {
        let client = Client::new(da_params.node_url.parse().unwrap());
        let account = LocalAccount::from_private_key(&da_params.private_key, 0).unwrap();
        let module_address = da_params.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&da_params.chain_id).expect("Invalid chain id");
        let trusted_setup = KzgSettings::load_trusted_setup_file(Path::new(&da_params.trusted_setup))
            .expect("Failed to load trusted setup");

        Self { client, account, module_address, chain_id, trusted_setup }
    }
}

#[async_trait]
impl DaClient for AptosDaClient {
    async fn publish_state_diff(&self, state_diff: Vec<Vec<u8>>, _to: &[u8; 32]) -> color_eyre::Result<String> {
        let data = prepare_blob(&state_diff, &self.trusted_setup).await?;

        let (blobs, commitments, proofs) = data
            .into_iter()
            .map(|(blob, commitment, proof)| {
                (
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

        let starknet_identity = Identifier::new(STARKNET_VALIDITY).unwrap();
        let blob_submit_identity = Identifier::new(BLOB_SUBMISSION).unwrap();

        for i in 0..BYTES_PER_BLOB / MAX_BLOB_PART_SIZE {
            let payload = TransactionPayload::EntryFunction(EntryFunction::new(
                ModuleId::new(self.account.address(), starknet_identity.clone()),
                blob_submit_identity.clone(),
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
            results.push(handle.await?);
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
            let hash: String = handle.await??;
            hashes_combined.push_str(&hash);
        }

        Ok(hashes_combined)
    }

    async fn verify_inclusion(&self, external_id: &str) -> color_eyre::Result<DaVerificationStatus> {
        let hash_id = external_id.to_string();

        let hashes = hash_id.split("0x").filter(|&s| !s.is_empty()).map(|s| s.to_string()).collect::<Vec<_>>();

        let txs = hashes
            .into_iter()
            .map(|hash_ptr| {
                let hash = HashValue::from_str(hash_ptr.as_str()).unwrap();
                let client = self.client.clone();
                tokio::spawn(async move {
                    let tx = client.get_transaction_by_hash(hash).await?;
                    Ok::<Transaction, RestError>(tx.into_inner())
                })
            })
            .collect::<Vec<_>>();

        for tx in txs {
            let tx = tx.await??;
            if !tx.success() {
                return Ok(DaVerificationStatus::Rejected(format!(
                    "Transaction {} failed",
                    tx.transaction_info().unwrap().hash
                )));
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

    use alloy::hex;
    use aptos_sdk::crypto::ValidCryptoMaterialStringExt;
    use aptos_sdk::move_types::u256;
    use aptos_sdk::types::chain_id::NamedChain::TESTING;
    use aptos_testcontainer::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};

    use super::*;

    const INIT_CONTRACT_STATE: &str = "initialize_contract_state";

    async fn aptos_init_state(da_client: &AptosDaClient) {
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(da_client.account.address(), Identifier::new(STARKNET_VALIDITY).unwrap()),
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
        let tx = build_transaction(payload, &da_client.account, da_client.chain_id);
        da_client.client.submit_and_wait(&tx).await.expect("Failed to init state!");
    }

    #[tokio::test]
    async fn test_aptos_da_client() -> anyhow::Result<()> {
        run(1, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await.unwrap();
                let node_url = aptos_container.get_node_url();

                let module_account_private_key = accounts.first().unwrap();
                let module_account = LocalAccount::from_private_key(module_account_private_key, 0).unwrap();

                let config = AptosDaValidatedArgs {
                    node_url,
                    private_key: module_account_private_key.to_string(),
                    module_address: module_account.address().to_string(),
                    chain_id: TESTING.id().to_string(),
                    trusted_setup: "./trusted_setup.txt".to_string(),
                };

                let da_client = AptosDaClient::new_with_args(&config).await;

                let mut named_address = HashMap::new();
                named_address.insert("starknet_addr".to_string(), module_account.address().to_string());
                aptos_container
                    .upload_contract(
                        "../../../ionia",
                        &module_account.private_key().to_encoded_string().unwrap(),
                        &named_address,
                        None,
                        false,
                    )
                    .await
                    .unwrap();

                let sequence_number =
                    da_client.client.get_account(da_client.account.address()).await?.into_inner().sequence_number;
                da_client.account.set_sequence_number(sequence_number);
                eprintln!("sequence_number = {:#?}", sequence_number);

                aptos_init_state(&da_client).await;

                let data = vec![hex::decode(include_str!("../test_utils/hex_block_630872.txt")).unwrap()];

                let result = da_client
                    .publish_state_diff(data, &u256::U256::from(0u128).to_le_bytes())
                    .await
                    .expect("Failed to submit blob!");
                eprintln!("result = {:#?}", result);

                let verify_inclusion = da_client.verify_inclusion(result.as_str()).await.unwrap();
                eprintln!("verify_inclusion = {:#?}", verify_inclusion);
                assert_eq!(verify_inclusion, DaVerificationStatus::Verified);
                Ok(())
            })
        })
        .await
    }
}
