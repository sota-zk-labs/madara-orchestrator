use aptos_sdk::types::LocalAccount;
use async_trait::async_trait;
use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};
use starknet::core::types::FieldElement;
use color_eyre::Result;
use mockall::{automock, predicate::*};

mod config;

pub struct AptosSettlementClient {
    wallet: LocalAccount,

}

#[automock]
#[async_trait]
impl SettlementClient for AptosSettlementClient {
    async fn register_proof(&self, proof: Vec<FieldElement>) -> Result<String> {
        todo!()
    }

    async fn update_state_calldata(
        &self,
        program_output: Vec<FieldElement>,
        onchain_data_hash: FieldElement,
        onchain_data_size: FieldElement
    ) -> Result<String> {
        todo!()
    }

    async fn update_state_blobs(
        &self,
        program_output: Vec<FieldElement>,
        kzg_proof: Vec<u8>
    ) -> Result<String> {
        todo!()
    }

    async fn verify_inclusion(&self, external_id: &str) -> Result<SettlementVerificationStatus> {
        todo!()
    }
}