use std::string::String;

use base64;
use hex;

use aes;
use analyzer;
use decryptor;
use utility::error::{Result, ResultExt};
use utility::file;
use utility::hamming;
use utility::xor;

// Challenge 1
pub fn hex_decode_base64(hex_string: &str) -> Result<String> {
    let normal_vec = hex::decode(hex_string).chain_err(|| "could not decode hex string")?;
    let base64_string = base64::encode(&normal_vec);

    Ok(base64_string)
}

// Challenge 2
pub fn string_xor(hex_string_1: &str, hex_string_2: &str) -> Result<String> {
    xor::string_xor(hex_string_1, hex_string_2)
}

// Challenge 3
pub fn break_single_byte_key_from_hex_string(
    cipher_string: &str,
) -> Result<decryptor::ByteKeyState> {
    let cipher_bytes = hex::decode(cipher_string).chain_err(|| "could not decode hex string")?;

    Ok(decryptor::break_single_byte_key(&cipher_bytes))
}

// Challenge 4
pub fn break_multiline_file_byte_key(
    file_path: &str,
) -> Result<decryptor::ByteKeyState> {
    let lines = file::buffered_file_reader(file_path)?;

    decryptor::break_lines_key(lines)
}

// Challenge 5
pub fn encode_with_repeating_key(plain_text: &str, key: &str) -> String {
    let cipher_vec = xor::repeating_key_xor(plain_text.as_bytes(), key.as_bytes());

    hex::encode(cipher_vec)
}

// Challenge 6
pub fn strings_hamming_distance(string_1: &str, string_2: &str) -> usize {
    hamming::bit_distance(string_1.as_bytes(), string_2.as_bytes())
}

pub fn break_xor_file_repeating_key(file_path: &str) -> Result<Vec<u8>> {
    let file_bytes = file::dump_bytes(file_path)?;
    let base64_config = base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        true,
        base64::LineWrap::NoWrap,
    );
    let cipher_bytes = base64::decode_config(&file_bytes, base64_config).chain_err(|| "could not decode base64 string")?;

    Ok(decryptor::break_repeating_key_xor(&cipher_bytes))
}

// Challenge 7
pub fn decrypt_aes_ecb_file(file_path: &str, key: &str) -> Result<String> {
    let file_bytes = file::dump_bytes(file_path)?;
    let base64_config = base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        true,
        base64::LineWrap::NoWrap,
    );
    let cipher_bytes = base64::decode_config(&file_bytes, base64_config).chain_err(|| "could not decode base64 string")?;
    let plaintext = aes::decrypt_ecb_text(&cipher_bytes, key.as_bytes())?;

    let new_string = String::from_utf8(plaintext).chain_err(|| "could not convert to UTF-8 string")?;
    Ok(new_string)
}

// Challenge 8
pub fn detect_ecb_file_line(file_path: &str) -> Result<usize> {
    let buffer = file::buffered_file_reader(file_path)?;

    analyzer::detect_ecb_line(buffer)
}
