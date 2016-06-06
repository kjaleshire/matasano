use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

pub fn decrypt_ecb_128_text(cipher_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let decryptor = AesSafe128Decryptor::new(key);

    decrypt_ecb_text(cipher_bytes, &decryptor)
}

pub fn encrypt_ecb_128_text(plain_text: &[u8], key: &[u8]) -> Vec<u8> {
    let encryptor = AesSafe128Encryptor::new(key);

    encrypt_ecb_text(plain_text, &encryptor)
}

pub fn decrypt_cbc_128_text(cipher_bytes: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let decryptor = AesSafe128Decryptor::new(key);

    decrypt_cbc_text(cipher_bytes, iv, &decryptor)
}

pub fn encrypt_cbc_128_text(plain_text: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let encryptor = AesSafe128Encryptor::new(key);

    encrypt_cbc_text(plain_text, iv, &encryptor)
}

pub fn decrypt_ecb_text<T>(cipher_bytes: &[u8], decryptor: &T) -> Vec<u8>
    where T: BlockDecryptor
{
    let mut decoded_vec = Vec::with_capacity(cipher_bytes.len());
    let mut write_buffer = vec![0; decryptor.block_size()];

    for cipher_block in cipher_bytes.chunks(decryptor.block_size()) {
        decryptor.decrypt_block(&cipher_block, &mut write_buffer);

        decoded_vec.extend_from_slice(&write_buffer);
    }

    decoded_vec
}

pub fn encrypt_ecb_text<T>(plain_text: &[u8], encryptor: &T) -> Vec<u8>
    where T: BlockEncryptor
{
    let mut encoded_vec = Vec::with_capacity(plain_text.len());
    let mut write_buffer = vec![0; encryptor.block_size()];

    for text_block in plain_text.chunks(encryptor.block_size()) {
        encryptor.encrypt_block(&text_block, &mut write_buffer);

        encoded_vec.extend_from_slice(&write_buffer);
    }

    encoded_vec
}

pub fn decrypt_cbc_text<T>(cipher_bytes: &[u8], iv: &[u8], decryptor: &T) -> Vec<u8>
    where T: BlockDecryptor
{
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

    decoded_vec
}

pub fn encrypt_cbc_text<T>(plain_text: &[u8], iv: &[u8], encryptor: &T) -> Vec<u8>
    where T: BlockEncryptor
{
    let mut encoded_vec = Vec::with_capacity(plain_text.len());
    let mut write_buffer = vec![0; encryptor.block_size()];

    write_buffer.clone_from_slice(iv);

    for text_block in plain_text.chunks(encryptor.block_size()) {
        let current_iv: Vec<u8> = text_block.iter()
            .zip(&write_buffer)
            .map(|(text_byte, iv_byte)| text_byte ^ iv_byte)
            .collect();

        encryptor.encrypt_block(&current_iv, &mut write_buffer);

        encoded_vec.extend_from_slice(&write_buffer);
    }

    encoded_vec
}

pub fn pkcs7_pad_vec(byte_vec: &mut Vec<u8>, block_size: usize) -> usize {
    let padded_len = padded_len(byte_vec.len(), block_size);
    let padding_size = padded_len - byte_vec.len();

    assert!(padding_size < block_size,
            "padding size must be less than block size");

    for _ in 0..padding_size {
        byte_vec.push(padding_size as u8);
    }

    padding_size
}

pub fn padded_len(length: usize, block_size: usize) -> usize {
    match length % block_size {
        0 => length,
        rem => length + block_size - rem,
    }
}
