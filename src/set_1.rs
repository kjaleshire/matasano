use serialize::base64::{Config,ToBase64,Standard,Newline};
use serialize::hex::{FromHex, ToHex};

use std::vec::Vec;

use english_text_util;
use file_util;
use hamming_util;

pub struct ByteKeyState {
    pub score: f32,
    pub key: u8,
    pub line: usize,
    pub string: String
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
pub fn hex_decode_base64(hex_string: &str) -> String {
    let base64_config = Config {
        char_set: Standard,
        newline: Newline::LF,
        pad: true,
        line_length: None
    };

    hex_string.from_hex().unwrap().to_base64(base64_config)
}

// Challenge 2
pub fn string_xor(hex_string_1: &str, hex_string_2: &str) -> String {
    let string1 = hex_string_1.from_hex().unwrap();
    let string2 = hex_string_2.from_hex().unwrap();

    string1.iter().zip(string2.iter()).map(|(&byte1, &byte2)| {
        byte1 ^ byte2
    }).collect::<Vec<u8>>()[..].to_hex()
}

// Challenge 3
pub fn break_single_line_byte_key(encoded_bytes: &[u8]) -> ByteKeyState {
    let initial_state = ByteKeyState{ score: 0.0, key: 0x0, line: 0, string: String::with_capacity(0) };

    (0x0u8..0xFFu8).fold(initial_state, |current_state, trial_key| {
        let decoded_vec = encoded_bytes.iter().map(|&byte| {
            byte ^ trial_key
        }).collect();
        match String::from_utf8(decoded_vec) {
            Ok(utf8_string) => {
                let score = english_text_util::string_score(&utf8_string[..]);
                match score > current_state.score {
                    true => ByteKeyState{ score: score, key: trial_key, line: 0, string: utf8_string },
                    false => current_state
                }
            },
            _ => current_state
        }
    })
}

// Challenge 4
pub fn break_multiline_file_byte_key(file_path: &str) -> ByteKeyState {
    let file_lines = file_util::lines_iterator(file_path);
    let initial_state = ByteKeyState{ score: 0.0, key: 0x0, line: 0, string: String::with_capacity(0) };

    file_lines.enumerate().fold(initial_state, |current_state, (next_line_number, next_line)| {
        let mut trial_state = break_single_line_byte_key(&next_line.unwrap().from_hex().unwrap()[..]);
        match trial_state.score > current_state.score {
            true => {
                trial_state.line = next_line_number;
                trial_state
            },
            false => current_state
        }
    })
}

// Challenge 5
pub fn repeating_key_xor(text: &str, key: &str) -> String {
    text.as_bytes().iter().zip(key.as_bytes().iter().cycle()).map(|(&byte, &byte_key)| {
        byte ^ byte_key
    }).collect::<Vec<u8>>()[..].to_hex()
}

// Challenge 6
pub fn challenge_6(cipher_bytes: &[u8]) -> Vec<u8> {
    let initial_state = KeyState{distance: 9000.0, size: 0};
    let min_key_size = 2;
    let max_key_size = 64;

    let size = (min_key_size..max_key_size).fold(initial_state, |current_state, key_size| {
        let passes = (cipher_bytes.len() / key_size) - 1;

        let normalized_distance = (0..passes).map(|index| {
            let slice_1 = &cipher_bytes[key_size*index..key_size*(index+1)];
            let slice_2 = &cipher_bytes[key_size*(index+1)..key_size*(index+2)];
            hamming_util::bit_distance(slice_1, slice_2)
        }).fold(0, |accumulator, distance| accumulator + distance) as f32 / (passes * key_size) as f32;

        match normalized_distance < current_state.distance {
            true => KeyState{ size: key_size, distance: normalized_distance },
            false => current_state
        }
    }).size;

    let number_of_blocks = cipher_bytes.len() / size;

    (0..size).map(|size_index|{
        let block: Vec<u8> = (0..number_of_blocks).map(|block_index|{
            cipher_bytes[block_index * size + size_index]
        }).collect();
        break_single_line_byte_key(&block[..]).key
    }).collect()
}
