use aptos_sdk::move_types::u256::U256;
use aptos_sdk::move_types::value::MoveValue;

pub(crate) fn slice_from_u8_to_u256(slice: &[u8; 32]) -> MoveValue {
    MoveValue::U256(U256::from_le_bytes(slice))
}

pub(crate) fn slice_from_vec_u8_to_u256(slices: &[[u8; 32]]) -> Vec<MoveValue> {
    slices.iter().map(slice_from_u8_to_u256).collect()
}
