use alloy::primitives::FixedBytes;

pub(crate) fn vec_fixed_bytes_48_to_hex_string(data: &Vec<FixedBytes<48>>) -> String {
    let hex_chars: Vec<String> = data.iter().map(|byte| format!("{:02X}", byte)).collect();
    hex_chars.join("")
}

pub(crate) fn vec_fixed_bytes_131072_to_hex_string(data: &Vec<FixedBytes<131072>>) -> String {
    let hex_chars: Vec<String> = data.iter().map(|byte| format!("{:02X}", byte)).collect();
    hex_chars.join("")
}