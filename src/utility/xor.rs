use hex;

use super::error::MatasanoError;

pub fn string_xor(hex_string_1: &str, hex_string_2: &str) -> Result<String, MatasanoError> {
    let byte_vec_1 = hex::decode(hex_string_1)?;
    let byte_vec_2 = hex::decode(hex_string_2)?;

    let result = byte_slice_xor(&byte_vec_1, &byte_vec_2)?;

    let new_hex_string = hex::encode(result);

    Ok(new_hex_string)
}

pub fn byte_slice_xor(byte_vec_1: &[u8], byte_vec_2: &[u8]) -> Result<Vec<u8>, MatasanoError> {
    if byte_vec_1.len() != byte_vec_2.len() {
        return Err(MatasanoError::Other("Hex strings must be of equal length"));
    }

    Ok(byte_vec_1.iter().zip(byte_vec_2).map(|(byte_1, byte_2)| byte_1 ^ byte_2).collect())
}

pub fn repeating_key_xor(plain_text: &[u8], key: &[u8]) -> Vec<u8> {
    key.iter()
        .cycle()
        .zip(plain_text)
        .map(|(key_byte, plain_text_byte)| key_byte ^ plain_text_byte)
        .collect()
}
