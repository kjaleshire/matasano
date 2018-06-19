use openssl::symm::{encrypt, Cipher, Crypter, Mode};
use rand::{self, distributions::Standard, Rng};

use utility::error::{Result, ResultExt};

pub fn decrypt_ecb_text(ciphertext_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    let mut plaintext = Vec::with_capacity(ciphertext_bytes.len());

    for ciphertext_block in ciphertext_bytes.chunks(cipher.block_size()) {
        let mut write_buffer = vec![0; cipher.block_size() + ciphertext_block.len()];
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)
            .chain_err(|| "Could not initializer crypter")?;
        crypter.pad(false);
        let count = crypter
            .update(ciphertext_block, &mut write_buffer)
            .chain_err(|| "Could not update plaintext buffer")?;
        let rest = crypter
            .finalize(&mut write_buffer[count..])
            .chain_err(|| "Could not finalize decryption")?;
        write_buffer.truncate(count + rest);

        plaintext.extend_from_slice(&write_buffer);
    }

    Ok(plaintext)
}

pub fn encrypt_ecb_text(plaintext_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    let mut ciphertext = Vec::with_capacity(plaintext_bytes.len());

    for plaintext_block in plaintext_bytes.chunks(cipher.block_size()) {
        let mut write_buffer = encrypt(cipher, key, None, plaintext_block)
            .chain_err(|| "Could not enrypt ecb plaintext")?;
        write_buffer.truncate(cipher.block_size());

        ciphertext.extend_from_slice(&write_buffer);
    }

    Ok(ciphertext)
}

pub fn decrypt_cbc_text(ciphertext_bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();

    let mut next_iv = iv;
    let mut plaintext = Vec::with_capacity(ciphertext_bytes.len());

    for ciphertext_block in ciphertext_bytes.chunks(cipher.block_size()) {
        let mut write_buffer = vec![0; cipher.block_size() + ciphertext_block.len()];
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)
            .chain_err(|| "Could not initializer crypter")?;
        crypter.pad(false);
        let count = crypter
            .update(ciphertext_block, &mut write_buffer)
            .chain_err(|| "Could not update plaintext buffer")?;
        let rest = crypter
            .finalize(&mut write_buffer[count..])
            .chain_err(|| "Could not finalize decryption")?;
        write_buffer.truncate(count + rest);

        let current_iv = next_iv;
        next_iv = &ciphertext_block;

        let mut xord_plaintext = write_buffer
            .iter()
            .zip(current_iv.iter())
            .map(|(decoded_byte, iv_byte)| decoded_byte ^ iv_byte)
            .collect();

        plaintext.append(&mut xord_plaintext);
    }

    Ok(plaintext)
}

pub fn encrypt_cbc_text(plaintext_bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();

    let mut write_buffer = vec![0; cipher.block_size()];
    let mut ciphertext = Vec::with_capacity(plaintext_bytes.len());

    write_buffer.copy_from_slice(iv);

    for plaintext_block in plaintext_bytes.chunks(cipher.block_size()) {
        let text_iv_block: Vec<u8> = plaintext_block
            .iter()
            .zip(&write_buffer)
            .map(|(text_byte, iv_byte)| text_byte ^ iv_byte)
            .collect();

        write_buffer = encrypt(cipher, key, None, &text_iv_block)
            .chain_err(|| "Could not encrypt cbc plaintext")?;
        write_buffer.truncate(cipher.block_size());

        ciphertext.extend_from_slice(&write_buffer);
    }

    Ok(ciphertext)
}

pub fn pkcs7_pad_vec(byte_vec: &mut Vec<u8>, block_size: usize) -> Result<usize> {
    let padded_len = padded_len(byte_vec.len(), block_size);
    let padding_size = padded_len - byte_vec.len();

    if padding_size >= block_size {
        bail!("padding size must be less than block size")
    }

    for _ in 0..padding_size {
        byte_vec.push(padding_size as u8);
    }

    Ok(padding_size)
}

pub fn strip_pkcs7_padding(plaintext: &str) -> Result<String> {
    match plaintext.chars().last() {
        Some(last_char) => {
            for test_char in plaintext.chars().rev().take(last_char as usize) {
                if test_char != last_char {
                    bail!("Invalid padding detected")
                }
            }

            Ok(String::from(
                &plaintext[..plaintext.len() - last_char as usize],
            ))
        }
        None => bail!("The plaintext is empty"),
    }
}

pub fn padded_len(length: usize, block_size: usize) -> usize {
    match length % block_size {
        0 => length,
        rem => length + block_size - rem,
    }
}

pub fn generate_random_aes_key(rng: &mut rand::ThreadRng, block_size: usize) -> Vec<u8> {
    rng.sample_iter(&Standard).take(block_size).collect()
}
