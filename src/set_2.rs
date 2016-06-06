use serialize::base64::{Config, FromBase64, Newline, Standard, ToBase64};

use std::collections::HashMap;
use std::str;

use aes;
use analyzer;
use cookie;
use decryptor;
use oracle::Oracle;
use utility::error::MatasanoError;
use utility::file;

// Challenge 9
pub fn pkcs_pad_string(str_slice: &str, block_size: usize) -> String {
    let mut string = String::from(str_slice);

    unsafe {
        aes::pkcs7_pad_vec(string.as_mut_vec(), block_size);
    }

    string
}

// Challenge 10
pub fn decrypt_encrypt_aes_cbc_file(file_path: &str,
                                    iv: &[u8],
                                    key: &str)
                                    -> Result<(String, Vec<u8>), MatasanoError> {
    let cipher_bytes = file::dump_bytes(file_path).unwrap()[..].from_base64().unwrap();

    let decoded_vec = aes::decrypt_cbc_128_text(&cipher_bytes, iv, key.as_bytes());

    Ok((String::from_utf8(decoded_vec)?, cipher_bytes))
}

pub fn encrypt_aes_cbc_text(plain_text: &str, iv: &[u8], key: &str) -> Vec<u8> {
    aes::encrypt_cbc_128_text(plain_text.as_bytes(), iv, key.as_bytes())
}

// Challenge 11
pub fn oracle_generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    let mut oracle = Oracle::new();

    (oracle.set_random_aes_key(), oracle.set_random_aes_key())
}

pub fn decrypt_encrypt_aes_ecb_file(file_path: &str,
                                    key: &str)
                                    -> Result<(String, Vec<u8>), MatasanoError> {
    let cipher_bytes = file::dump_bytes(file_path).unwrap()[..].from_base64().unwrap();

    let decoded_vec = aes::decrypt_ecb_128_text(&cipher_bytes, key.as_bytes());

    Ok((String::from_utf8(decoded_vec)?, cipher_bytes))
}

pub fn encrypt_aes_ecb_text(plain_text: &str, key: &str) -> Vec<u8> {
    aes::encrypt_ecb_128_text(plain_text.as_bytes(), key.as_bytes())
}

pub fn oracle_encrypt_and_guess() -> (analyzer::Mode, analyzer::Mode) {
    let mut oracle = Oracle::new();

    let cipher_bytes = oracle.randomly_mangled_encrypted_text();
    let detected_mode = analyzer::detect_encryption_mode(&cipher_bytes, 16);

    (detected_mode, oracle.last_mode)
}

// Challenge 12
pub fn detect_oracle_block_size<'a>(append_str: &'a str,
                                    try_up_to: usize)
                                    -> Result<usize, MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str(&append_str)?;

    analyzer::detect_oracle_block_size(&mut |block| oracle.randomly_append_and_encrypt_text(block),
                                       try_up_to)
}

pub fn detect_oracle_mode<'a>(append_str: &'a str)
                              -> Result<(analyzer::Mode, analyzer::Mode), MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str(&append_str)?;

    let trial_block = vec![0x65 as u8; 128];

    let encoded_vec = oracle.randomly_append_and_encrypt_text(&trial_block)?;

    Ok((analyzer::detect_encryption_mode(&encoded_vec, 16), analyzer::Mode::Ecb))
}

pub fn decrypt_append_str<'a>(append_str: &'a str) -> Result<String, MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str(&append_str)?;

    let decoded_vec = decryptor::break_oracle_append_fn(&mut |block| {
            oracle.randomly_append_and_encrypt_text(block)
        })
        ?;

    Ok(String::from_utf8(decoded_vec)?)
}

// Challenge 13
pub fn deserialize_profile<'a>(encoded_profile: &'a str) -> HashMap<String, String> {
    cookie::parse(encoded_profile)
}

pub fn serialized_profile_for<'a>(email: &'a str) -> String {
    cookie::profile_for(email)
}

// pub fn decrypt_encrypted_profile<'a>(email: &'a str) -> Result<Vec<u8>, MatasanoError> {
//     let serialized_profile = cookie::profile_for(email);
//     let mut oracle = Oracle::new();
//     let encrypted_profile =
//         aes::encrypt_ecb_128_text(serialized_profile.as_bytes(), &oracle.key);
//     let base64_config = Config {
//         char_set: Standard,
//         newline: Newline::LF,
//         pad: true,
//         line_length: None,
//     };
//     oracle.append_vec = Some(encrypted_profile.to_base64(base64_config).into());
//
//     decryptor::break_oracle_append_fn(&mut |block| {
//         let email = str::from(block)?;
//         Ok(cookie::profile_for(&email))
//     })
// }
