#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
use async_trait::async_trait;
use avail_subxt::api::runtime_types::avail_core::AppId;
use avail_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use avail_subxt::avail::Client;
use avail_subxt::primitives::AvailExtrinsicParams;
use avail_subxt::{api, AvailConfig};
use color_eyre::eyre;
use mockall::automock;
use subxt::ext::sp_core::sr25519::Pair;

use config::AvailConfig as AvailDaConfig;
use da_client_interface::{DaClient, DaVerificationStatus};

use crate::conversion::get_bytes_from_state_diff;

type AvailPairSigner = subxt::tx::PairSigner<AvailConfig, Pair>;

pub mod config;
pub mod conversion;

pub struct AvailDaClient {
    client: Client,
    app_id: AppId,
    signer: AvailPairSigner,
}

#[automock]
#[async_trait]
impl DaClient for AvailDaClient {
    async fn publish_state_diff(&self, state_diff: Vec<Vec<u8>>, _to: &[u8; 32]) -> eyre::Result<String> {
        let client = &self.client;
        let bytes = BoundedVec(get_bytes_from_state_diff(state_diff));
        let data_transfer = api::tx().data_availability().submit_data(bytes);
        let extrinsic_params = AvailExtrinsicParams::new_with_app_id(self.app_id);
        let tx = client.tx().sign_and_submit(&data_transfer, &self.signer, extrinsic_params).await?;

        Ok(tx.to_string())
    }

    // This function might be unused because if the transaction is successful, the publish_state_diff
    // will return the transaction hash. Otherwise, this function will panic.
    #[allow(unused)]
    async fn verify_inclusion(&self, _external_id: &str) -> eyre::Result<DaVerificationStatus> {
        Ok(DaVerificationStatus::Verified)
    }

    async fn max_blob_per_txn(&self) -> u64 {
        todo!()
    }

    async fn max_bytes_per_blob(&self) -> u64 {
        todo!()
    }
}

impl AvailDaClient {
    #[allow(dead_code)]
    async fn from(config: AvailDaConfig) -> eyre::Result<Self> {
        let client = Client::from_url(config.provider).await.expect("Failed to create new client.");
        let app_id = AppId::from(config.app_id);
        let pair =
            <Pair as subxt::ext::sp_core::Pair>::from_string(&config.seed, None).expect("Failed to load signer.");
        let signer = AvailPairSigner::new(pair);
        Ok(AvailDaClient { client, app_id, signer })
    }
}
