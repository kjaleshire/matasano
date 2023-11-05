use serialize::base64::{Config, FromBase64, Newline, Standard, ToBase64};
use serialize::hex::{FromHex, ToHex};

use aes;
use analyzer;
use decryptor;
use utility::error::MatasanoError;
use utility::file;
use utility::hamming;
use utility::xor;

// Challenge 1
pub fn hex_decode_base64(hex_string: &str) -> Result<String, MatasanoError> {
    let base64_config = Config {
        char_set: Standard,
        newline: Newline::LF,
        pad: true,
        line_length: None,
    };

    Ok(hex_string.from_hex()?.to_base64(base64_config))
}

// Challenge 2
pub fn string_xor(hex_string_1: &str, hex_string_2: &str) -> Result<String, MatasanoError> {
    let byte_vec_1 = hex_string_1.from_hex()?;
    let byte_vec_2 = hex_string_2.from_hex()?;

    if byte_vec_1.len() != byte_vec_2.len() {
        return Err(MatasanoError::Other("Hex strings must be of equal length"));
    }

    let result: Vec<u8> = byte_vec_1.iter()
        .zip(byte_vec_2)
        .map(|(byte_1, byte_2)| byte_1 ^ byte_2)
        .collect();

    Ok(result[..].to_hex())
}

// Challenge 3
pub fn break_single_byte_key_from_hex_string(cipher_string: &str) -> Result<decryptor::ByteKeyState, MatasanoError> {
    let cipher_bytes = cipher_string.from_hex()?;

    Ok(decryptor::break_single_byte_key(&cipher_bytes))
}

// Challenge 4
pub fn break_multiline_file_byte_key(file_path: &str) -> Result<decryptor::ByteKeyState, MatasanoError> {
    let lines = file::buffered_file_reader(file_path)?;

    decryptor::break_lines_key(lines)
}

// Challenge 5
pub fn encode_with_repeating_key(plain_text: &str, key: &str) -> String {
    let cipher_vec = xor::repeating_key_xor(plain_text.as_bytes(), key.as_bytes());

    cipher_vec.to_hex()
}

// Challenge 6
pub fn strings_hamming_distance(string_1: &str, string_2: &str) -> usize {
    hamming::bit_distance(string_1.as_bytes(), string_2.as_bytes())
}

pub fn break_xor_file_repeating_key(file_path: &str) -> Result<Vec<u8>, MatasanoError> {
    let cipher_bytes = file::dump_bytes(file_path)?[..].from_base64()?;

    Ok(decryptor::break_repeating_key_xor(&cipher_bytes))
}

// Challenge 7
pub fn decrypt_aes_ecb_file(file_path: &str, key: &str) -> Result<String, MatasanoError> {
    let cipher_bytes = file::dump_bytes(file_path)?[..].from_base64()?;

    Ok(String::from_utf8(aes::decrypt_ecb_128_text(&cipher_bytes, key.as_bytes()))?)
}

// Challenge 8
pub fn detect_ecb_file_line(file_path: &str) -> Result<usize, MatasanoError> {
    let buffer = file::buffered_file_reader(file_path)?;

    analyzer::detect_ecb_line(buffer)
}
