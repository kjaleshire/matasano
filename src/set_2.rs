use crypto::aessafe;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

use encryption_oracle;
use error::MatasanoError;
use set_1;

// Challenge 9
pub fn pkcs_pad_string(byte_vec: &mut Vec<u8>, block_size: usize) -> usize {
    let padded_len = padded_len(byte_vec.len(), block_size);
    let padding_size = padded_len - byte_vec.len();

    for _ in 0..padding_size {
        byte_vec.push(0x04);
    }

    padding_size
}

pub fn padded_len(length: usize, block_size: usize) -> usize {
    match length % block_size {
        0 => length,
        rem => length + block_size - rem
    }
}

// Challenge 10
pub fn decrypt_aes_cbc_text(cipher_bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<String, MatasanoError> {
    let decryptor = aessafe::AesSafe128Decryptor::new(key);

    let mut decoded_vec = Vec::with_capacity(cipher_bytes.len());
    let mut write_buffer = vec![0; decryptor.block_size()];
    let mut current_iv = iv;

    for cipher_block in cipher_bytes.chunks(decryptor.block_size()) {
        decryptor.decrypt_block(&cipher_block, &mut write_buffer);

        for (decoded_byte, iv_byte) in write_buffer.iter().zip(current_iv.iter()) {
            decoded_vec.push(decoded_byte ^ iv_byte);
        }

        current_iv = &cipher_block;
    }

    Ok(String::from_utf8(decoded_vec)?)
}

pub fn encrypt_aes_cbc_text(plain_text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let encryptor = aessafe::AesSafe128Encryptor::new(key);

    let mut encoded_vec = Vec::with_capacity(plain_text.len());
    let mut write_buffer = vec![0; encryptor.block_size()];

    write_buffer.clone_from_slice(iv);

    for text_block in plain_text.chunks(encryptor.block_size()) {
        let current_iv: Vec<u8> = text_block.iter().zip(&write_buffer).map(|(text_byte, iv_byte)|
            text_byte ^ iv_byte
        ).collect();

        encryptor.encrypt_block(&current_iv, &mut write_buffer);

        encoded_vec.extend_from_slice(&write_buffer);
    }

    encoded_vec
}

// Challenge 11
pub fn encrypt_aes_ebc_text(plain_text: &[u8], key: &[u8]) -> Vec<u8> {
    let encryptor = aessafe::AesSafe128Encryptor::new(key);

    let mut encoded_vec = Vec::with_capacity(plain_text.len());
    let mut write_buffer = vec![0; encryptor.block_size()];

    for text_block in plain_text.chunks(encryptor.block_size()) {
        encryptor.encrypt_block(&text_block, &mut write_buffer);

        encoded_vec.extend_from_slice(&write_buffer);
    }

    encoded_vec
}

pub fn detect_encryption_mode(cipher_bytes: &[u8]) -> encryption_oracle::EncryptionMode {
    match (0..16).any(|index| set_1::is_ecb_encrypted(&cipher_bytes[index..])) {
        true => encryption_oracle::EncryptionMode::Ecb,
        false => encryption_oracle::EncryptionMode::Cbc
    }
}
