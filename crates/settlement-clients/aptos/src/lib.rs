use std::path::PathBuf;
use std::str::FromStr;

use alloy::eips::eip4844::BYTES_PER_BLOB;
use aptos_sdk::crypto::HashValue;
use aptos_sdk::move_types::account_address::AccountAddress;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::{serialize_values, MoveValue};
use aptos_sdk::rest_client::aptos_api_types::{EntryFunctionId, TransactionData, ViewRequest};
use aptos_sdk::rest_client::Client;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::LocalAccount;
use async_trait::async_trait;
use c_kzg::{Blob, Bytes32, KzgCommitment, KzgProof, KzgSettings};
use color_eyre::eyre::{bail, eyre, Ok};
use color_eyre::Result;
mod helper;
mod types;

use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use lazy_static::lazy_static;
use mockall::automock;
use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};
#[cfg(feature = "testing")]
use utils::env_utils::get_env_var_or_panic;

use crate::helper::{build_transaction, build_transaction_with_nonce};
use crate::types::{bytes_be_to_u128, convert_stark_bigint_to_u256};

pub const ENV_PRIVATE_KEY: &str = "MADARA_ORCHESTRATOR_APTOS_PRIVATE_KEY";
const X_0_POINT_OFFSET: usize = 10;
const Y_LOW_POINT_OFFSET: usize = 14;
const Y_HIGH_POINT_OFFSET: usize = Y_LOW_POINT_OFFSET + 1;

const STARKNET_VALIDITY: &str = "starknet_validity";
const UPDATE_STATE: &str = "update_state";
const UPDATE_STATE_KZG_DA: &str = "update_state_kzg_da";
const STATE_BLOCK_NUMBER: &str = "state_block_number";

// Aptos Transaction Finality
const TIMEOUT_TX_FINALISATION: u64 = 2;

lazy_static! {
    pub static ref PROJECT_ROOT: PathBuf = PathBuf::from(format!("{}/../../../", env!("CARGO_MANIFEST_DIR")));
    pub static ref KZG_SETTINGS: KzgSettings = KzgSettings::load_trusted_setup_file(
        &PROJECT_ROOT.join("crates/settlement-clients/aptos/src/trusted_setup.txt")
    )
    .expect("Error loading trusted setup file");
}

#[derive(Clone, Debug)]
pub struct AptosSettlementValidatedArgs {
    pub node_url: String,
    pub private_key: String,
    pub module_address: String,
    pub chain_id: String,
}

pub struct AptosSettlementClient {
    pub client: Client,
    pub account: LocalAccount,
    pub module_address: AccountAddress,
    pub chain_id: ChainId,
}

impl AptosSettlementClient {
    pub fn new_with_args(settlement_cfg: &AptosSettlementValidatedArgs) -> Self {
        let client = Client::new(settlement_cfg.node_url.parse().unwrap());
        let account = LocalAccount::from_private_key(&settlement_cfg.private_key, 0).unwrap();
        let module_address = settlement_cfg.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&settlement_cfg.chain_id).expect("Invalid chain id");
        Self { client, account, module_address, chain_id }
    }

    #[cfg(feature = "testing")]
    pub fn with_test_params(
        provider: RootProvider<Http<Client>>,
        core_contract_address: Address,
        rpc_url: Url,
        impersonate_account: Option<Address>,
    ) -> Self {
        todo!();
    }

    /// Build kzg proof for the x_0 point evaluation
    pub fn build_proof(
        blob_data: Vec<Vec<u8>>,
        x_0_value: Bytes32,
        y_0_value_program_output: Bytes32,
    ) -> Result<KzgProof> {
        // Assuming that there is only one blob in the whole Vec<Vec<u8>> array for now.
        // Later we will add the support for multiple blob in single blob_data vec.
        assert_eq!(blob_data.len(), 1);

        let fixed_size_blob: [u8; BYTES_PER_BLOB] = blob_data[0].as_slice().try_into()?;

        let blob = Blob::new(fixed_size_blob);
        let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, &KZG_SETTINGS)?;
        let (kzg_proof, y_0_value) = KzgProof::compute_kzg_proof(&blob, &x_0_value, &KZG_SETTINGS)?;

        if y_0_value != y_0_value_program_output {
            bail!(
                "ERROR : y_0 value is different than expected. Expected {:?}, got {:?}",
                y_0_value,
                y_0_value_program_output
            );
        }

        // Verifying the proof for double check
        let eval = KzgProof::verify_kzg_proof(
            &commitment.to_bytes(),
            &x_0_value,
            &y_0_value,
            &kzg_proof.to_bytes(),
            &KZG_SETTINGS,
        )?;

        if !eval { Err(eyre!("ERROR : Assertion failed, not able to verify the proof.")) } else { Ok(kzg_proof) }
    }
}

#[automock]
#[async_trait]
impl SettlementClient for AptosSettlementClient {
    /// Should register the proof on the base layer and return an external id
    /// which can be used to track the status.
    #[allow(unused)]
    async fn register_proof(&self, proof: [u8; 32]) -> Result<String> {
        todo!("register_proof is not implemented yet")
    }

    /// Should be used to update state on core contract when DA is done in calldata
    async fn update_state_calldata(
        &self,
        program_output: Vec<[u8; 32]>,
        onchain_data_hash: [u8; 32],
        onchain_data_size: [u8; 32],
    ) -> Result<String> {
        tracing::info!(
            log_type = "starting",
            category = "update_state",
            function_type = "calldata",
            "Updating state with calldata."
        );
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
                    &MoveValue::U256(U256::from_le_bytes(&onchain_data_size)),
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

        tracing::info!(
            log_type = "completed",
            category = "update_state",
            function_type = "calldata",
            tx_hash = %transaction_info.hash.to_string(),
            "State updated with calldata."
        );

        Ok(transaction_info.hash.to_string())
    }

    /// Should be used to update state on core contract when DA is in blobs/alt DA
    async fn update_state_with_blobs(
        &self,
        program_output: Vec<[u8; 32]>,
        state_diff: Vec<Vec<u8>>,
        nonce: u64,
    ) -> Result<String> {
        tracing::info!(
            log_type = "starting",
            category = "update_state",
            function_type = "blobs",
            "Updating state with blobs."
        );

        // calculating y_0 point
        let y_0 = Bytes32::from(
            convert_stark_bigint_to_u256(
                bytes_be_to_u128(&program_output[Y_LOW_POINT_OFFSET]),
                bytes_be_to_u128(&program_output[Y_HIGH_POINT_OFFSET]),
            )
            .to_be_bytes(),
        );

        // x_0_value : program_output[10]
        // Updated with starknet 0.13.2 spec
        let kzg_proof = Self::build_proof(
            state_diff,
            Bytes32::from_bytes(program_output[X_0_POINT_OFFSET].as_slice())
                .expect("Not able to get x_0 point params."),
            y_0,
        )
        .expect("Unable to build KZG proof for given params.")
        .to_owned();

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

        #[cfg(feature = "testing")]
        let pending_transaction = {
            todo!();
            let txn_request = {
                test_config::configure_transaction(self.provider.clone(), tx_envelope, self.impersonate_account).await
            };
            self.provider.send_transaction(txn_request).await?
        };

        #[cfg(not(feature = "testing"))]
        let pending_transaction =
            self.client.submit(&signed_txn).await.expect("Failed to submit update state transaction").into_inner();

        tracing::info!(
            log_type = "completed",
            category = "update_state",
            function_type = "blobs",
            "State updated with blobs."
        );

        log::warn!("⏳ Waiting for txn finality.......");

        let res = self.wait_for_tx_finality(&pending_transaction.hash.to_string()).await?;

        match res {
            Some(_) => {
                log::info!("Txn hash : {:?} Finalized ✅", pending_transaction.hash.to_string());
            }
            None => {
                log::error!("Txn hash not finalised");
            }
        }
        Ok(pending_transaction.hash.to_string())
    }

    /// Should verify the inclusion of a tx in the settlement layer
    async fn verify_tx_inclusion(&self, tx_hash: &str) -> Result<SettlementVerificationStatus> {
        tracing::info!(
            log_type = "starting",
            category = "verify_tx",
            function_type = "inclusion",
            tx_hash = %tx_hash,
            "Verifying tx inclusion."
        );
        let client = self.client.clone();

        let hash = HashValue::from_str(tx_hash.strip_prefix("0x").unwrap())?;
        let txn = client.get_transaction_by_hash_bcs(hash).await?;

        let (maybe_pending_txn, _) = txn.into_parts();
        match maybe_pending_txn {
            TransactionData::OnChain(txn) => {
                let status = txn.info.status();
                if status.is_success() {
                    tracing::info!(
                        log_type = "completed",
                        category = "verify_tx",
                        function_type = "inclusion",
                        tx_hash = %tx_hash,
                        "Tx inclusion verified."
                    );
                    Ok(SettlementVerificationStatus::Verified)
                } else {
                    tracing::info!(
                        log_type = "pending",
                        category = "verify_tx",
                        function_type = "inclusion",
                        tx_hash = %tx_hash,
                        "Tx inclusion pending."
                    );
                    Ok(SettlementVerificationStatus::Rejected(format!(
                        "Transaction {} have been rejected: {}",
                        tx_hash,
                        txn.info.to_string()
                    )))
                }
            }
            TransactionData::Pending(_) => {
                tracing::info!(
                    log_type = "pending",
                    category = "verify_tx",
                    function_type = "inclusion",
                    tx_hash = %tx_hash,
                    "Tx inclusion pending."
                );
                Ok(SettlementVerificationStatus::Pending)
            }
        }
    }

    /// Wait for a pending tx to achieve finality
    async fn wait_for_tx_finality(&self, tx_hash: &str) -> Result<Option<u64>> {
        let hash = HashValue::from_str(tx_hash.strip_prefix("0x").unwrap())?;
        let tx = self.client.wait_for_transaction_by_hash(hash, TIMEOUT_TX_FINALISATION, None, None).await?;
        Ok(tx.into_inner().transaction_info().unwrap().block_height.map(|block_height| block_height.0))
    }

    /// Get the last block settled through the core contract
    async fn get_last_settled_block(&self) -> Result<u64> {
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
        Ok(block_number.parse()?)
    }

    async fn get_nonce(&self) -> Result<u64> {
        Ok(self.client.get_account(self.account.address()).await?.into_inner().sequence_number)
    }
}

#[cfg(feature = "testing")]
mod test_config {
    use alloy::network::TransactionBuilder;
    use alloy::rpc::types::TransactionRequest;

    use super::*;

    #[allow(dead_code)]
    pub async fn configure_transaction(
        provider: Arc<RootProvider<Http<Client>>>,
        tx_envelope: TxEnvelope,
        impersonate_account: Option<Address>,
    ) -> TransactionRequest {
        let mut txn_request: TransactionRequest = tx_envelope.into();

        // IMPORTANT to understand #[cfg(test)], #[cfg(not(test))] and SHOULD_IMPERSONATE_ACCOUNT
        // Two tests :  `update_state_blob_with_dummy_contract_works` &
        // `update_state_blob_with_impersonation_works` use a env var `SHOULD_IMPERSONATE_ACCOUNT` to inform
        // the function `update_state_with_blobs` about the kind of testing,
        // `SHOULD_IMPERSONATE_ACCOUNT` can have any of "0" or "1" value :
        //      - if "0" then : Testing via default Anvil address.
        //      - if "1" then : Testing via impersonating `Starknet Operator Address`.
        // Note : changing between "0" and "1" is handled automatically by each test function, `no` manual
        // change in `env.test` is needed.
        if let Some(impersonate_account) = impersonate_account {
            let nonce =
                provider.get_transaction_count(impersonate_account).await.unwrap().to_string().parse::<u64>().unwrap();
            txn_request.set_nonce(nonce);
            txn_request = txn_request.with_from(impersonate_account);
        }

        txn_request
    }
}
