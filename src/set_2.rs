use base64;

use std::{collections::HashMap, str};

use aes;
use analyzer;
use cookie;
use decryptor;
use oracle::Oracle;
use utility::{error::MatasanoError, file};

// Challenge 9
pub fn pkcs_pad_string(str_slice: &str, block_size: usize) -> String {
    let mut string = String::from(str_slice);

    unsafe {
        aes::pkcs7_pad_vec(string.as_mut_vec(), block_size);
    }

    string
}

// Challenge 10
pub fn decrypt_encrypted_aes_cbc_file(
    file_path: &str,
    key: &str,
    iv: &[u8],
) -> Result<(String, Vec<u8>), MatasanoError> {
    let rawfile_bytes = file::dump_bytes(file_path)?;
    let base64_config = base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        true,
        base64::LineWrap::NoWrap,
    );
    let cipher_bytes = base64::decode_config(&rawfile_bytes, base64_config)?;

    let decoded_vec = aes::decrypt_cbc_text(&cipher_bytes, key.as_bytes(), iv);

    Ok((String::from_utf8(decoded_vec)?, cipher_bytes))
}

pub fn encrypt_aes_cbc_text(plaintext: &str, key: &str, iv: &[u8]) -> Vec<u8> {
    aes::encrypt_cbc_text(plaintext.as_bytes(), key.as_bytes(), iv)
}

// Challenge 11
pub fn oracle_generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    let mut oracle = Oracle::new();

    (oracle.set_random_aes_key(), oracle.set_random_aes_key())
}

pub fn decrypt_encrypt_aes_ecb_file(
    file_path: &str,
    key: &str,
) -> Result<(String, Vec<u8>), MatasanoError> {
    let rawfile_bytes = file::dump_bytes(file_path)?;
    let base64_config = base64::Config::new(
        base64::CharacterSet::Standard,
        true,
        true,
        base64::LineWrap::NoWrap,
    );
    let cipher_bytes = base64::decode_config(&rawfile_bytes, base64_config)?;

    let decoded_vec = aes::decrypt_ecb_text(&cipher_bytes, key.as_bytes());

    Ok((String::from_utf8(decoded_vec)?, cipher_bytes))
}

pub fn encrypt_aes_ecb_text(plaintext: &str, key: &str) -> Vec<u8> {
    aes::encrypt_ecb_text(plaintext.as_bytes(), key.as_bytes())
}

pub fn oracle_encrypt_and_guess() -> (analyzer::Mode, analyzer::Mode) {
    let mut oracle = Oracle::new();

    let cipher_bytes = oracle.randomly_mangled_encrypted_text();
    let detected_mode = analyzer::detect_encryption_mode(&cipher_bytes, 16);

    (detected_mode, oracle.last_mode)
}

// Challenge 12
pub fn detect_oracle_block_size(
    append_str: &str,
    try_up_to: usize,
) -> Result<usize, MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str(&append_str)?;

    analyzer::detect_oracle_block_size(
        &mut |plaintext| oracle.randomly_append_prepend_and_encrypt_text(plaintext),
        try_up_to,
    )
}

pub fn detect_oracle_mode(
    append_str: &str,
) -> Result<(analyzer::Mode, analyzer::Mode), MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str(&append_str)?;

    let trial_block = vec![0x65 as u8; 128];

    let encoded_vec = oracle.randomly_append_prepend_and_encrypt_text(&trial_block)?;

    Ok((
        analyzer::detect_encryption_mode(&encoded_vec, 16),
        analyzer::Mode::Ecb,
    ))
}

pub fn decrypt_append_str(append_str: &str) -> Result<String, MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str(&append_str)?;

    let decoded_vec = decryptor::break_oracle_append_fn(&mut |block| {
        oracle.randomly_append_prepend_and_encrypt_text(block)
    })?;

    Ok(String::from_utf8(decoded_vec)?)
}

// Challenge 13
pub fn deserialize_cookie(encoded_cookie: &str) -> HashMap<String, String> {
    cookie::Cookie::deserialize_cookie(encoded_cookie)
}

pub fn serialized_profile_for(email: &str) -> String {
    let cookie = cookie::Cookie::new();
    cookie.profile_for(email)
}

pub fn create_cookie() -> cookie::Cookie {
    cookie::Cookie::new()
}

pub fn encrypted_profile_for(cookie: &cookie::Cookie, email: &str) -> Vec<u8> {
    cookie.encrypted_profile_for(email)
}

pub fn decrypted_profile_from(
    cookie: &cookie::Cookie,
    encrypted_profile: &[u8],
) -> cookie::Profile {
    cookie.decrypted_profile_for(encrypted_profile)
}

pub fn craft_encrypted_admin_profile(cookie: &cookie::Cookie) -> Vec<u8> {
    let mut malicious_block = Vec::from("admin");
    let _padding = aes::pkcs7_pad_vec(&mut malicious_block, cookie.block_size());

    let (matching_blocks, _, mut first_encrypted_profile) =
        decryptor::find_matching_blocks(
            &mut |plaintext| {
                let mut malicious_email =
                    String::from_utf8(plaintext.to_vec()).expect("not a utf8 string");
                Ok(cookie.encrypted_profile_for(&mut malicious_email))
            },
            &malicious_block,
            cookie.block_size(),
        ).expect("Could not find matching blocks");
    let mut second_encrypted_profile;

    let mut admin_block = first_encrypted_profile.split_off(matching_blocks * cookie.block_size());
    admin_block.truncate(cookie.block_size());
    // At this point we have the admin block we're going to append to our malicious profile

    // Now we need to discover how long our email needs to be to slice of the `user------------` portion
    let mut username = String::from("fo");
    let create_email = |username: &str| format!("{}@bar.com", username);

    first_encrypted_profile = cookie.encrypted_profile_for(&create_email(&username));
    let message_len = first_encrypted_profile.len();
    username.push('o');
    second_encrypted_profile = cookie.encrypted_profile_for(&create_email(&username));

    while first_encrypted_profile.len() == second_encrypted_profile.len() {
        first_encrypted_profile = second_encrypted_profile;
        username.push('o');
        second_encrypted_profile = cookie.encrypted_profile_for(&create_email(&username));
    }

    username.push_str("ooo");
    first_encrypted_profile = cookie.encrypted_profile_for(&create_email(&username));
    first_encrypted_profile.truncate(message_len);
    first_encrypted_profile.append(&mut admin_block);
    first_encrypted_profile
}

// Challenge 14
pub fn decrypt_append_str_with_random_prepend(append_str: &str) -> Result<String, MatasanoError> {
    let mut oracle = Oracle::new_with_base64_append_str_and_random_prepend(&append_str)?;

    let decoded_vec = decryptor::break_oracle_append_prepend_fn(&mut |plaintext| {
        oracle.randomly_append_prepend_and_encrypt_text(plaintext)
    })?;

    Ok(String::from_utf8(decoded_vec)?)
}
