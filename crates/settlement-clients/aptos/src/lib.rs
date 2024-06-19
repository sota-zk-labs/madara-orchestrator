#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use aptos_sdk::crypto::{HashValue, ValidCryptoMaterialStringExt};
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::move_types::account_address::AccountAddress;
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::{MoveValue, serialize_values};
use aptos_sdk::rest_client::aptos_api_types::{EntryFunctionId, ViewRequest};
use aptos_sdk::rest_client::Client;
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::{AccountKey, LocalAccount};
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::EntryFunction;
use aptos_sdk::types::transaction::TransactionPayload;
use async_trait::async_trait;
use color_eyre::eyre;
use mockall::automock;

use settlement_client_interface::{SettlementClient, SettlementVerificationStatus};

use crate::config::AptosSettlementConfig;
use crate::conversion::slice_from_vec_u8_to_u256;

pub mod config;
pub mod conversion;

pub struct AptosSettlementClient {
    pub client: Client,
    pub account: LocalAccount,
    pub module_address: AccountAddress,
    pub chain_id: ChainId,
}

const STARKNET_VALIDITY: &str = "starknet_validity";
const UPDATE_STATE: &str = "update_state";
const UPDATE_STATE_KZG_DA: &str = "update_state_kzg_da";

impl From<AptosSettlementConfig> for AptosSettlementClient {
    fn from(config: AptosSettlementConfig) -> Self {
        let client = Client::new(config.node_url.parse().unwrap());
        let private_key =
            Ed25519PrivateKey::from_encoded_string(&config.private_key).expect("Failed to parse private key");
        let account_key = AccountKey::from(private_key);
        let account_address = config.account_address.parse().expect("Invalid account address");
        let account = LocalAccount::new(account_address, account_key, 0);
        let module_address = config.module_address.parse().expect("Invalid module address");
        let chain_id = ChainId::from_str(&config.chain_id).expect("Invalid chain id");

        AptosSettlementClient { client, account, module_address, chain_id }
    }
}

const STATE_BLOCK_NUMBER: &'static str = "state_block_number";

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
        let sequence_number =
            self.client.get_account(self.account.address()).await.unwrap().into_inner().sequence_number;
        self.account.set_sequence_number(sequence_number);
        let sequencer_number = self.account.increment_sequence_number();

        // Build the transaction payload
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

        let txn = TransactionBuilder::new(
            payload,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60,
            self.chain_id,
        )
            .sender(self.account.address())
            .sequence_number(sequencer_number)
            .max_gas_amount(10000)
            .gas_unit_price(100)
            .build();

        let signed_txn = self.account.sign_transaction(txn);

        let tx = self
            .client
            .submit_and_wait(&signed_txn)
            .await
            .expect("Failed to submit update state transaction")
            .into_inner();

        Ok(tx.transaction_info().unwrap().hash.to_string())
    }

    async fn update_state_with_blobs(&self, program_output: Vec<[u8; 32]>, state_diff: Vec<Vec<u8>>) -> color_eyre::Result<String> {
        unimplemented!("hee-hee")
    }

    async fn update_state_blobs(&self, program_output: Vec<[u8; 32]>, kzg_proof: [u8; 48]) -> color_eyre::Result<String> {
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(self.account.address(), Identifier::new(STARKNET_VALIDITY).unwrap()),
            Identifier::new(UPDATE_STATE_KZG_DA).unwrap(),
            vec![],
            serialize_values(
                vec![
                    &MoveValue::Vector(slice_from_vec_u8_to_u256(&program_output)),
                    &MoveValue::vector_u8(kzg_proof.to_vec()),
                ]
                    .into_iter(),
            ),
        ));

        let txn = TransactionBuilder::new(
            payload,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60,
            self.chain_id,
        )
            .sender(self.account.address())
            .sequence_number(self.account.sequence_number())
            .max_gas_amount(10000)
            .gas_unit_price(100)
            .build();

        let signed_txn = self.account.sign_transaction(txn);

        let tx = self
            .client
            .submit_and_wait(&signed_txn)
            .await
            .expect("Failed to submit update state transaction")
            .into_inner();

        Ok(tx.transaction_info().unwrap().hash.to_string())
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
        eprintln!("block_number = {:#?}", block_number);
        Ok(block_number.parse::<u64>().unwrap())
    }
}

#[cfg(test)]
#[allow(unused)]
#[allow(dead_code)]
mod test {
    use std::time::{SystemTime, UNIX_EPOCH};

    use aptos_sdk::move_types::identifier::Identifier;
    use aptos_sdk::move_types::language_storage::ModuleId;
    use aptos_sdk::move_types::u256;
    use aptos_sdk::move_types::value::{MoveValue, serialize_values};
    use aptos_sdk::transaction_builder::TransactionBuilder;
    use aptos_sdk::types::account_address::AccountAddress;
    use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};

    use settlement_client_interface::{SettlementClient, SettlementConfig};

    use crate::{AptosSettlementClient, STARKNET_VALIDITY};
    use crate::config::AptosSettlementConfig;

    const INIT_CONTRACT_STATE: &'static str = "initialize_contract_state";

    #[tokio::test]
    async fn init_state() {
        let settlement_client = setup();

        let client = settlement_client.client;
        let account = settlement_client.account;
        let chain_id = settlement_client.chain_id;
        let module_address = settlement_client.module_address;

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

    const REGISTER_FACT: &'static str = "register_fact";
    const FACT_REGISTRY: &'static str = "fact_registry";

    #[tokio::test]
    async fn test_update_state_calldata() {
        let settlement_client = setup();

        let client = &settlement_client.client;
        let account = &settlement_client.account;
        let chain_id = &settlement_client.chain_id;
        let module_address = &settlement_client.module_address;

        let sequence_number = client.get_account(account.address()).await.unwrap().into_inner().sequence_number;
        account.set_sequence_number(sequence_number);
        let sequencer_number = account.increment_sequence_number();

        // Registry the precompute fact
        let tx_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(EntryFunction::new(
                ModuleId::new(*module_address, Identifier::new(FACT_REGISTRY).unwrap()),
                Identifier::new(REGISTER_FACT).unwrap(),
                vec![],
                serialize_values(
                    vec![&MoveValue::vector_u8(
                        hex::decode("f195ea8e7b7f7b7e54d44ad364d0de013312eb2ed153cde90aaa751e091f1940").unwrap(),
                    )]
                        .into_iter(),
                ),
            )),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60,
            *chain_id,
        )
            .sender(account.address())
            .sequence_number(sequencer_number)
            .max_gas_amount(10000)
            .gas_unit_price(100)
            .build();

        let signed_txn = account.sign_transaction(tx_builder);
        let tx =
            client.submit_and_wait(&signed_txn).await.expect("Failed to submit fact registry transaction").into_inner();

        let program_output: Vec<[u8; 32]> = vec![
            u256::U256::from(1u128).to_le_bytes(), // Global root
            u256::U256::from(1u128).to_le_bytes(), // Message offset
            u256::U256::from(2u128).to_le_bytes(), // Block number offset
            u256::U256::from(2u128).to_le_bytes(), // Block hash offset
            u256::U256::from(0u128).to_le_bytes(), // Config hash offset
            u256::U256::from(0u128).to_le_bytes(),
            u256::U256::from(0u128).to_le_bytes(),
            u256::U256::from(0u128).to_le_bytes(),
        ];
        let onchain_data_hash = u256::U256::from(1u128).to_le_bytes();
        let onchain_data_size = 1usize;

        settlement_client
            .update_state_calldata(program_output, onchain_data_hash, onchain_data_size)
            .await
            .expect("Failed to update state!");
    }

    async fn test_update_state_kzg_da() {}

    #[tokio::test]
    async fn test_get_last_settled_block() {
        let settlement_client = setup();
        let block = settlement_client.get_last_settled_block().await.expect("Failed to get last settled block!");
        eprintln!("block = {:#?}", block);
    }

    fn setup() -> AptosSettlementClient {
        let config = AptosSettlementConfig::new_from_env();
        let settlement_client = AptosSettlementClient::from(config);
        settlement_client
    }
}
