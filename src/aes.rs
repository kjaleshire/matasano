use openssl::symm::{encrypt, Cipher, Crypter, Mode};
use rand::{self, Rng};

pub fn decrypt_ecb_text(ciphertext_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    ciphertext_bytes
        .chunks(cipher.block_size())
        .flat_map(|ciphertext_block| {
            let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)
                .expect("Could not initializer crypter");
            crypter.pad(false);
            let mut write_buffer = vec![0; ciphertext_block.len() + cipher.block_size()];
            let count = crypter
                .update(ciphertext_block, &mut write_buffer)
                .expect("Could not update plaintext buffer");
            let rest = crypter
                .finalize(&mut write_buffer[count..])
                .expect("Could not finalize decryption");
            write_buffer.truncate(count + rest);

            write_buffer.clone()
        })
        .collect()
}

pub fn encrypt_ecb_text(plaintext_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    plaintext_bytes
        .chunks(cipher.block_size())
        .flat_map(|plaintext_block| {
            let mut write_buffer = encrypt(cipher, key, None, plaintext_block)
                .expect("Could not enrypt ecb plaintext");
            write_buffer.truncate(cipher.block_size());

            write_buffer.clone()
        })
        .collect()
}

pub fn decrypt_cbc_text(ciphertext_bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let mut next_iv = iv;

    ciphertext_bytes
        .chunks(cipher.block_size())
        .flat_map(|ciphertext_block| {
            let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)
                .expect("Could not initializer crypter");
            crypter.pad(false);
            let mut write_buffer = vec![0; ciphertext_block.len() + cipher.block_size()];
            let count = crypter
                .update(ciphertext_block, &mut write_buffer)
                .expect("Could not update plaintext buffer");
            let rest = crypter
                .finalize(&mut write_buffer[count..])
                .expect("Could not finalize decryption");
            write_buffer.truncate(count + rest);

            let current_iv = next_iv;
            next_iv = &ciphertext_block;

            write_buffer
                .iter()
                .zip(current_iv.iter())
                .map(|(decoded_byte, iv_byte)| decoded_byte ^ iv_byte)
                .collect::<Vec<u8>>()
        })
        .collect()
}

pub fn encrypt_cbc_text(plaintext_bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let mut write_buffer = vec![0; cipher.block_size()];

    write_buffer.copy_from_slice(iv);

    plaintext_bytes
        .chunks(cipher.block_size())
        .flat_map(|plaintext_block| {
            let text_iv_block: Vec<u8> = plaintext_block
                .iter()
                .zip(&write_buffer)
                .map(|(text_byte, iv_byte)| text_byte ^ iv_byte)
                .collect();

            write_buffer = encrypt(cipher, key, None, &text_iv_block)
                .expect("Could not encrypt cbc plaintext");
            write_buffer.truncate(cipher.block_size());

            write_buffer.clone()
        })
        .collect()
}

pub fn pkcs7_pad_vec(byte_vec: &mut Vec<u8>, block_size: usize) -> usize {
    let padded_len = padded_len(byte_vec.len(), block_size);
    let padding_size = padded_len - byte_vec.len();

    assert!(
        padding_size < block_size,
        "padding size must be less than block size"
    );

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

pub fn generate_random_aes_key(rng: &mut rand::ThreadRng, block_size: usize) -> Vec<u8> {
    (0..block_size).map(|_| rng.gen()).collect()
}
