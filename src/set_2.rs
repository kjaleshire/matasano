use serialize::base64::FromBase64;

use aes;
use analyzer;
use analyzer::Mode;
use oracle::Oracle;
use utility::error::MatasanoError;
use utility::file;

// Challenge 9
pub fn pkcs_pad_string(str_slice: &str, block_size: usize) -> String {
    let mut string = String::from(str_slice);

    unsafe {
        aes::pkcs_pad_vec(string.as_mut_vec(), block_size);
    }

    string
}

// Challenge 10
pub fn decrypt_encrypt_aes_cbc_file(file_path: &str, iv: &[u8], key: &str) -> Result<(String, Vec<u8>), MatasanoError> {
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

    (oracle.generate_random_aes_key(), oracle.generate_random_aes_key())
}

pub fn decrypt_encrypt_aes_ecb_file(file_path: &str, key: &str) -> Result<(String, Vec<u8>), MatasanoError> {
    let cipher_bytes = file::dump_bytes(file_path).unwrap()[..].from_base64().unwrap();

    let decoded_vec = aes::decrypt_ecb_128_text(&cipher_bytes, key.as_bytes());

    Ok((String::from_utf8(decoded_vec)?, cipher_bytes))
}

pub fn encrypt_aes_ecb_text(plain_text: &str, key: &str) -> Vec<u8> {
    aes::encrypt_ecb_128_text(plain_text.as_bytes(), key.as_bytes())
}

pub fn oracle_encrypt_and_guess() -> (Mode, Mode) {
    let mut oracle = Oracle::new();

    let cipher_bytes = oracle.randomly_mangled_encrypted_text();
    let detected_mode = analyzer::detect_encryption_mode(&cipher_bytes);

    (detected_mode, oracle.last_mode)
}
