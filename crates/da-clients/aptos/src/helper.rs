use alloy::hex;
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{SignedTransaction, TransactionPayload};
use aptos_sdk::types::{AccountKey, LocalAccount};
use std::time::SystemTime;

pub(crate) fn build_transaction(
    payload: TransactionPayload,
    sender: &LocalAccount,
    chain_id: ChainId,
) -> SignedTransaction {
    let i = sender.increment_sequence_number();
    let tx = TransactionBuilder::new(
        payload,
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + 60,
        chain_id,
    )
    .sender(sender.address())
    .sequence_number(i)
    .max_gas_amount(100000)
    .gas_unit_price(100)
    .build();
    sender.sign_transaction(tx)
}

pub(crate) fn from_private_key(private_key: &str, sequencer_number: u64) -> color_eyre::Result<LocalAccount> {
    let key = AccountKey::from_private_key(Ed25519PrivateKey::try_from(
        hex::decode(private_key.trim_start_matches("0x"))?.as_ref(),
    )?);
    let address = key.authentication_key().account_address();
    Ok(LocalAccount::new(address, key, sequencer_number))
}
