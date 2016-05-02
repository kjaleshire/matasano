use crypto::aessafe;
use crypto::symmetriccipher::BlockDecryptor;

use serialize::base64::{Config, Newline, Standard, ToBase64};
use serialize::hex::{FromHex, ToHex};

use std::str;

use english_text_util;
use error::MatasanoError;
use file_util;
use hamming_util;

pub struct ByteKeyState {
    pub score: f32,
    pub key: u8,
    pub line: usize,
    pub string: String,
}

pub struct KeyState {
    pub distance: f32,
    pub size: usize,
}

impl Copy for KeyState {}
impl Clone for KeyState {
    fn clone(&self) -> KeyState { *self }
}

// Challenge 1
pub fn hex_decode_base64(hex_string: &str) -> Result<String, MatasanoError> {
    let base64_config = Config {
        char_set: Standard,
        newline: Newline::LF,
        pad: true,
        line_length: None
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

    let result: Vec<u8> = byte_vec_1.iter().zip(byte_vec_2).map(|(byte_1, byte_2)| {
        byte_1 ^ byte_2
    }).collect();

    Ok(result[..].to_hex())
}

// Challenge 3
pub fn break_single_line_byte_key(cipher_bytes: &[u8]) -> ByteKeyState {
    let initial_state = ByteKeyState{
                            score: 0.0,
                            key: 0x0,
                            line: 0,
                            string: String::with_capacity(0)
                        };

    let mut decoded_vec = Vec::with_capacity(cipher_bytes.len());

    (0u8..255).fold(initial_state, |current_state, trial_key_byte| {
        decoded_vec.clear();

        for cipher_byte in cipher_bytes {
            decoded_vec.push(cipher_byte ^ trial_key_byte);
        }

        match str::from_utf8(&decoded_vec) {
            Ok(str_slice) => {
                let score = english_text_util::string_score(str_slice);

                match score > current_state.score {
                    true => ByteKeyState{
                        score: score,
                        key: trial_key_byte,
                        line: 0,
                        string: String::from(str_slice)
                    },
                    false => current_state
                }
            },
            Err(_) => current_state
        }
    })
}

// Challenge 4
pub fn break_multiline_file_byte_key(file_path: &str) -> Result<ByteKeyState, MatasanoError> {
    let file_lines = file_util::lines_iterator(file_path)?;
    let initial_state = ByteKeyState{
                            score: 0.0,
                            key: 0x0,
                            line: 0,
                            string: String::with_capacity(0)
                        };

    file_lines.enumerate().fold(Ok(initial_state), |state, (next_line_number, next_line)| {
        let current_state = state?;
        let line = next_line?.from_hex()?;
        let mut trial_state = break_single_line_byte_key(&line);

        match trial_state.score > current_state.score {
            true => {
                trial_state.line = next_line_number + 1;
                Ok(trial_state)
            },
            false => {
                Ok(current_state)
            }
        }
    })
}

// Challenge 5
pub fn repeating_key_xor(plain_text: &[u8], key: &[u8]) -> String {
    let repeating_key = key.iter().cycle();

    repeating_key.zip(plain_text).map(|(key_byte, plain_text_byte)| {
        key_byte ^ plain_text_byte
    }).collect::<Vec<u8>>().to_hex()
}

// Challenge 6
pub fn break_repeating_key_xor_string(cipher_bytes: &[u8]) -> Vec<u8> {
    let initial_state = KeyState{distance: 9000.0, size: 0};
    let min_key_size = 2;
    let max_key_size = 64;

    let key_size = (min_key_size..max_key_size).fold(initial_state, |current_state, trial_size| {
        let passes = (cipher_bytes.len() / trial_size) - 1;

        let sum_distance = (0..passes).map(|index| {
            let slice_1 = &cipher_bytes[trial_size*index..trial_size*(index+1)];
            let slice_2 = &cipher_bytes[trial_size*(index+1)..trial_size*(index+2)];
            hamming_util::bit_distance(slice_1, slice_2)
        }).fold(0, |a, s| a + s);

        let normalized_distance = sum_distance as f32 / (passes * trial_size) as f32;

        match normalized_distance < current_state.distance {
            true => KeyState{ size: trial_size, distance: normalized_distance },
            false => current_state
        }
    }).size;

    let number_of_blocks = cipher_bytes.len() / key_size;

    let mut block = Vec::with_capacity(number_of_blocks);

    (0..key_size).map(|size_index| {
        block.clear();

        for block_index in 0..number_of_blocks {
            block.push(cipher_bytes[block_index * key_size + size_index]);
        }

        break_single_line_byte_key(&block).key
    }).collect()
}

// Challenge 7
pub fn decrypt_aes_ecb_text(cipher_bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let decryptor = aessafe::AesSafe128Decryptor::new(key);

    let mut decoded_vec = Vec::with_capacity(cipher_bytes.len());
    let mut write_buffer = vec![0; decryptor.block_size()];

    for cipher_block in cipher_bytes.chunks(decryptor.block_size()) {
        decryptor.decrypt_block(&cipher_block, &mut write_buffer);

        decoded_vec.extend_from_slice(&write_buffer);
    }

    decoded_vec
}

// Challenge 8
pub fn detect_ecb_file_line(file_path: &str) -> Result<usize, MatasanoError> {
    let file_lines = file_util::lines_iterator(file_path)?;

    for (line_number, line) in file_lines.enumerate() {
        let line_bytes = line?.from_hex()?;

        if is_ecb_encrypted(&line_bytes) {
            return Ok(line_number + 1);
        }
    };

    Err(MatasanoError::Other("No match found in any lines"))
}

pub fn is_ecb_encrypted(byte_slice: &[u8]) -> bool {
    for (index, chunk) in byte_slice[..].chunks(16).enumerate() {
        if byte_slice[..].chunks(16).skip(index + 1).any(|other| chunk == other) {
            return true;
        }
    }
    false
}
