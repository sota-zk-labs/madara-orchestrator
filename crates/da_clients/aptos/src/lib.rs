#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
use aptos_sdk::rest_client::Client;
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::LocalAccount;
use aptos_sdk::types::transaction::{SignedTransaction, TransactionPayload};
use async_trait::async_trait;
use alloy::primitives::{bytes, FixedBytes, U256};
use c_kzg::{Blob, BYTES_PER_BLOB, KzgCommitment, KzgProof, KzgSettings};
use da_client_interface::{DaClient, DaVerificationStatus};
use dotenv::dotenv;

pub mod config;

pub struct AptosDaClient {
    #[allow(dead_code)]
    client: Client,
    wallet: LocalAccount,
    trusted_setup: KzgSettings,
}

#[async_trait]
impl DaClient for AptosDaClient {
    async fn publish_state_diff(&self, state_diff: Vec<Vec<u8>>) -> color_eyre::Result<String> {
        dotenv.ok();
        let client = &self.client;
        let wallet = &self.wallet;

        let (sidecar_blobs, sidecar_commitments, sidecar_proofs) = prepare_sidecar(&state_diff, &self.trusted_setup).await?;

        /// Prepare transaction payload to store blob data
        let payload = TransactionPayload::EntryFunction("").into_entry_function().args();

        /// Build transaction
        let txn = TransactionBuilder::new(
            payload,
            wallet.address(),
            wallet.sequence_number(),
        )
            .chain_id(ChainId::test())
            .max_gas_amount(1000)
            .gas_unit_price(1)
            .build();

        /// Sign transaction
        let signed_txn: SignedTransaction = wallet.sign_transaction(txn);

        /// Submit transaction
        let response = client.submit(&signed_txn).await?;
    }

    async fn verify_inclusion(&self, external_id: &str) -> color_eyre::Result<DaVerificationStatus> {
        todo!()
    }

    async fn max_blob_per_txn(&self) -> u64 {
        /// This number can be changed in the future, we will decide this value later.
        6
    }

    async fn max_bytes_per_blob(&self) -> u64 {
        /// Similar with max_blob_per_txn
        131072
    }
}

async fn prepare_sidecar(
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