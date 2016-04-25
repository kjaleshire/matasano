use crypto::{aes, blockmodes, buffer};

use serialize::base64::{Config, Newline, Standard, ToBase64};
use serialize::hex::{FromHex, ToHex};

use std::vec::Vec;

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
    let string1 = hex_string_1.from_hex()?;
    let string2 = hex_string_2.from_hex()?;

    if string1.len() != string2.len() {
        return Err(MatasanoError::Other("Hex strings must be of equal length"));
    }

    let mut result = Vec::with_capacity(string1.len());

    for (&byte1, &byte2) in string1.iter().zip(string2.iter()) {
        result.push(byte1 ^ byte2);
    }

    Ok(result[..].to_hex())
}

// Challenge 3
pub fn break_single_line_byte_key(encoded_bytes: &[u8]) -> ByteKeyState {
    let initial_state = ByteKeyState{ score: 0.0, key: 0x0, line: 0, string: String::with_capacity(0) };

    (0u8..255).fold(initial_state, |current_state, trial_key| {
        let mut decoded_vec = Vec::with_capacity(encoded_bytes.len());

        for byte in encoded_bytes.iter() {
            decoded_vec.push(byte ^ trial_key);
        }

        match String::from_utf8(decoded_vec) {
            Ok(utf8_string) => {
                let score = english_text_util::string_score(&utf8_string[..]);
                match score > current_state.score {
                    true => ByteKeyState{ score: score, key: trial_key, line: 0, string: utf8_string },
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
    let initial_state = ByteKeyState{ score: 0.0, key: 0x0, line: 0, string: String::with_capacity(0) };

    let result = file_lines.enumerate().fold(initial_state, |current_state, (next_line_number, next_line)| {
        if let Ok(line) = next_line {
            let mut trial_state = break_single_line_byte_key(&line.from_hex().unwrap()[..]);
            if trial_state.score > current_state.score {
                trial_state.line = next_line_number + 1;
                return trial_state;
            }
        }
        current_state
    });

    Ok(result)
}

// Challenge 5
pub fn repeating_key_xor(text: &str, key: &str) -> String {
    let mut encoded_bytes = Vec::with_capacity(text.len());

    let text_iter = text.as_bytes().iter();
    let key_cycle = key.as_bytes().iter().cycle();

    for (byte, byte_key) in text_iter.zip(key_cycle) {
        encoded_bytes.push(byte ^ byte_key);
    }

    encoded_bytes[..].to_hex()
}

// Challenge 6
pub fn break_repeating_key_xor_string(cipher_bytes: &[u8]) -> Vec<u8> {
    let initial_state = KeyState{distance: 9000.0, size: 0};
    let min_key_size = 2;
    let max_key_size = 64;

    let key_size = (min_key_size..max_key_size).fold(initial_state, |current_state, trial_size| {
        let passes = (cipher_bytes.len() / trial_size) - 1;

        let mut sum_distance = 0;

        for index in 0..passes {
            let slice_1 = &cipher_bytes[trial_size*index..trial_size*(index+1)];
            let slice_2 = &cipher_bytes[trial_size*(index+1)..trial_size*(index+2)];
            sum_distance += hamming_util::bit_distance(slice_1, slice_2);
        }

        let normalized_distance = sum_distance as f32 / (passes * trial_size) as f32;

        match normalized_distance < current_state.distance {
            true => KeyState{ size: trial_size, distance: normalized_distance },
            false => current_state
        }
    }).size;

    let number_of_blocks = cipher_bytes.len() / key_size;

    let mut full_key = Vec::with_capacity(key_size);

    for size_index in 0..key_size {
        let mut block = Vec::with_capacity(number_of_blocks);

        for block_index in 0..number_of_blocks {
            block.push(cipher_bytes[block_index * key_size + size_index]);
        }

        full_key.push(break_single_line_byte_key(&block[..]).key);
    }

    full_key
}

// Challenge 7
pub fn decrypt_aes_ecb_text(cipher_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, MatasanoError> {
    let mut decoded_vec = vec![0; cipher_bytes.len()];

    {
        let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::PkcsPadding);

        let mut write_buffer = buffer::RefWriteBuffer::new(&mut decoded_vec[..]);

        let mut read_buffer = buffer::RefReadBuffer::new(cipher_bytes);

        decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
    }

    Ok(decoded_vec)
}

// Challenge 8
pub fn detect_ecb_file_line(file_path: &str) -> Result<usize, MatasanoError> {
    let file_lines = file_util::lines_iterator(file_path)?;

    for (line_number, line) in file_lines.enumerate() {
        let line_as_bytes = line?.from_hex()?;

        for (index, chunk) in line_as_bytes[..].chunks(16).enumerate() {
            for other_chunk in line_as_bytes[(index + 1) * 16..].chunks(16) {
                if chunk == other_chunk {
                    return Ok(line_number + 1);
                }
            }
        }
    };

    Err(MatasanoError::Other("No match found in any lines"))
}
