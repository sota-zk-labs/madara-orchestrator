#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use aptos_sdk::rest_client::{Client};
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::LocalAccount;
use aptos_sdk::types::transaction::{SignedTransaction, TransactionPayload, EntryFunction};
use async_trait::async_trait;
use alloy::primitives::FixedBytes;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256;
use aptos_sdk::move_types::value::{MoveValue, serialize_values};
use c_kzg::{Blob, BYTES_PER_BLOB, KzgCommitment, KzgProof, KzgSettings};
use da_client_interface::{DaClient, DaVerificationStatus};
use dotenv::dotenv;
use crate::config::AptosDaConfig;
use crate::conversion::{vec_fixed_bytes_131072_to_hex_string, vec_fixed_bytes_48_to_hex_string};

pub mod config;
pub mod conversion;

pub struct AptosDaClient {
    #[allow(dead_code)]
    client: Client,
    account: LocalAccount,
    trusted_setup: KzgSettings,
}

#[async_trait]
impl DaClient for AptosDaClient {
    async fn publish_state_diff(&self, state_diff: Vec<Vec<u8>>, _to: &[u8; 32]) -> color_eyre::Result<String> {
        dotenv().ok();
        let client = &self.client;
        let account = &self.account;

        let (blobs, commitments, proofs) = prepare_blob(&state_diff, &self.trusted_setup).await?;

        let payload = TransactionPayload::EntryFunction(
            EntryFunction::new(
                ModuleId::new(
                    account.address(),
                    Identifier::new("starknet").unwrap()
                ),
                Identifier::new("update_state").unwrap(),
                vec![],
                serialize_values(vec![
                    &MoveValue::Vector(vec![
                        MoveValue::U256(u256::U256::from_str(vec_fixed_bytes_131072_to_hex_string(&blobs).as_str()).unwrap()),
                        MoveValue::U256(u256::U256::from_str(vec_fixed_bytes_48_to_hex_string(&commitments).as_str()).unwrap()),
                        MoveValue::U256(u256::U256::from_str(vec_fixed_bytes_48_to_hex_string(&proofs).as_str()).unwrap()),
                    ])
                ].into_iter())
            )
        );

        // Build transaction.
        let txn = TransactionBuilder::new(
            payload,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ChainId::test())
            .sender(account.address())
            .sequence_number(1)
            .max_gas_amount(10000000)
            .gas_unit_price(1)
            .build();

        // Sign transaction.
        let signed_txn: SignedTransaction = account.sign_transaction(txn);

        // Submit transaction.
        client.submit(&signed_txn).await?;

        Ok(signed_txn.committed_hash().to_string())
    }

    async fn verify_inclusion(&self, external_id: &str) -> color_eyre::Result<DaVerificationStatus> {
        let client = &self.client;
        let txn = client.get_transaction_by_hash(HashValue::from_str(external_id).unwrap()).await?;
        let response = txn.into_inner();
        match response.success() {
            true => {
                Ok(DaVerificationStatus::Verified)
            }
            false => {
                match response.is_pending() {
                    true => {
                        Ok(DaVerificationStatus::Pending)
                    }
                    false => {
                        Ok(DaVerificationStatus::Rejected)
                    }
                }
            }
        }
    }

    async fn max_blob_per_txn(&self) -> u64 {
        // This number can be changed in the future, we will decide this value later.
        6
    }

    async fn max_bytes_per_blob(&self) -> u64 {
        // Similar with max_blob_per_txn
        131072
    }
}

impl From<AptosDaConfig> for AptosDaClient {
    fn from(config: AptosDaConfig) -> Self {
        let client = Client::new(config.node_url.parse().unwrap());
        let private_key = config.private_key.parse()?;
        let account_address = config.account_address.parse()?;
        let account = LocalAccount::new(account_address, private_key, 0);
        let trusted_setup = KzgSettings::load_trusted_setup_file(Path::new("./trusted_setup.txt"))
            .expect("Issue while loading the trusted setup");
        AptosDaClient { client, account, trusted_setup}
    }
}

async fn prepare_blob(
    state_diff: &[Vec<u8>],
    trusted_setup: &KzgSettings,
) -> color_eyre::Result<(Vec<FixedBytes<131072>>, Vec<FixedBytes<48>>, Vec<FixedBytes<48>>)> {
    let mut sidecar_blobs = vec![];
    let mut sidecar_commitments = vec![];
    let mut sidecar_proofs = vec![];

    for blob_data in state_diff {
        let mut fixed_size_blob: [u8; BYTES_PER_BLOB] = [0; BYTES_PER_BLOB];
        fixed_size_blob.copy_from_slice(blob_data.as_slice());

        let blob = Blob::new(fixed_size_blob);

        let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, trusted_setup)?;
        let proof = KzgProof::compute_blob_kzg_proof(&blob, &commitment.to_bytes(), trusted_setup)?;

        sidecar_blobs.push(FixedBytes::new(fixed_size_blob));
        sidecar_commitments.push(FixedBytes::new(commitment.to_bytes().into_inner()));
        sidecar_proofs.push(FixedBytes::new(proof.to_bytes().into_inner()));
    }

    Ok((sidecar_blobs, sidecar_commitments, sidecar_proofs))
}