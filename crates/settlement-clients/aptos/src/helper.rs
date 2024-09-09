use std::time::SystemTime;

use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{SignedTransaction, TransactionPayload};
use aptos_sdk::types::LocalAccount;

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
    .max_gas_amount(30000)
    .gas_unit_price(100)
    .build();
    sender.sign_transaction(tx)
}

pub(crate) fn build_transaction_with_nonce(
    payload: TransactionPayload,
    sender: &LocalAccount,
    chain_id: ChainId,
    sequence_number: u64,
) -> SignedTransaction {
    let tx = TransactionBuilder::new(
        payload,
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + 60,
        chain_id,
    )
    .sender(sender.address())
    .sequence_number(sequence_number)
    .max_gas_amount(30000)
    .gas_unit_price(100)
    .build();
    sender.sign_transaction(tx)
}
