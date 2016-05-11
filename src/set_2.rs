use serialize::base64::FromBase64;

use std::collections::HashMap;

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
    let detected_mode = analyzer::detect_encryption_mode(&cipher_bytes, 16);

    (detected_mode, oracle.last_mode)
}

// Challenge 12
pub fn detect_oracle_block_size<'a>(append_str: &'a str, try_up_to: usize) -> Result<usize, MatasanoError> {
    let mut oracle = Oracle::new_with_append_str(&append_str);

    let trial_block = vec![0x65 as u8; try_up_to * 2];

    for trial_block_size in 1..try_up_to + 1 {
        let encoded_vec = oracle.randomly_append_and_encrypt_text(&trial_block[..trial_block_size * 2])?;

        if encoded_vec[..trial_block_size] == encoded_vec[trial_block_size..trial_block_size * 2] {
            return Ok(trial_block_size)
        }
    }

    Err(MatasanoError::Other("block size not detected"))
}

pub fn detect_oracle_mode<'a>(append_str: &'a str) -> Result<(analyzer::Mode, analyzer::Mode), MatasanoError> {
    let mut oracle = Oracle::new_with_append_str(&append_str);

    let trial_block = vec![0x65 as u8; 128];

    let encoded_vec = oracle.randomly_append_and_encrypt_text(&trial_block)?;

    Ok((analyzer::detect_encryption_mode(&encoded_vec, 16), Mode::Ecb))
}

pub fn decrypt_append_str<'a>(append_str: &'a str) -> Result<String, MatasanoError> {
    let mut oracle = Oracle::new_with_append_str(&append_str);
    let mut dictionary = HashMap::new();

    oracle.append_str = Some(&append_str);

    let block_size = detect_oracle_block_size(append_str, 32)?;

    let decoded_size = oracle.randomly_append_and_encrypt_text(&[0; 0])?.len();

    let mut decoded_vec = Vec::with_capacity(decoded_size + block_size);
    decoded_vec.resize(block_size - 1, 0x65);

    'blocks: for block_index in 0..(decoded_size / block_size) {
        for byte_index in 0..block_size {
            let block_base = block_index * block_size;

            generate_dictionary(&mut dictionary, &decoded_vec[block_base + byte_index..], &mut oracle)?;

            let encoded_vec = oracle.randomly_append_and_encrypt_text(&decoded_vec[..block_size - byte_index - 1])?;

            match dictionary.get(&encoded_vec[block_base..block_base + block_size]) {
                Some(value) => {
                    match value.last() {
                        Some(&1) => break 'blocks,
                        Some(&last_byte) => decoded_vec.push(last_byte),
                        None => return Err(MatasanoError::Other("How do we have an empty vec here"))
                    }
                },
                None => {
                    return Err(MatasanoError::Other("No match for key"))
                }
            }
        }
    }
    Ok(String::from_utf8(decoded_vec.split_off(block_size - 1))?)
}

fn generate_dictionary(dictionary: &mut HashMap<Vec<u8>, Vec<u8>>, prefix_block: &[u8], oracle: &mut Oracle<&str>) -> Result<(), MatasanoError> {
    let mut trial_vec = Vec::with_capacity(prefix_block.len() + 1);

    trial_vec.extend_from_slice(prefix_block);

    dictionary.clear();

    for index in 0..u8::max_value() {
        trial_vec.push(index);
        let encoded_vec = oracle.randomly_append_and_encrypt_text(&trial_vec)?;

        dictionary.insert(encoded_vec[..prefix_block.len() + 1].to_vec(), trial_vec.clone());

        let _ = trial_vec.pop();
    }

    Ok(())
}
