use serialize::hex::FromHex;

use std::io::BufRead;
use std::str;

use utility::english;
use utility::error::MatasanoError;
use utility::hamming;

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

pub fn break_single_byte_key(cipher_bytes: &[u8]) -> ByteKeyState {
    let initial_state = ByteKeyState{ score: 0.0, key: 0, line: 0, string: String::with_capacity(0) };

    let mut decoded_vec = Vec::with_capacity(cipher_bytes.len());

    (0u8..255).fold(initial_state, |current_state, trial_key_byte| {
        decoded_vec.clear();

        for cipher_byte in cipher_bytes {
            decoded_vec.push(cipher_byte ^ trial_key_byte);
        }

        match str::from_utf8(&decoded_vec) {
            Ok(str_slice) => {
                let score = english::string_score(str_slice);

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

pub fn break_lines_key<T>(cipher_lines: T) -> Result<ByteKeyState, MatasanoError> where T: BufRead {
    let initial_state = ByteKeyState{ score: 0.0, key: 0x0, line: 0, string: String::with_capacity(0) };

    cipher_lines.lines().enumerate().fold(Ok(initial_state), |state, (next_line_number, next_line)| {
        let current_state = state?;
        let line = next_line?.from_hex()?;
        let mut trial_state = break_single_byte_key(&line);

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

pub fn break_repeating_key_xor(cipher_bytes: &[u8]) -> Vec<u8> {
    let initial_state = KeyState{distance: 9000.0, size: 0};
    let min_key_size = 2;
    let max_key_size = 64;

    let key_size = (min_key_size..max_key_size).fold(initial_state, |current_state, trial_size| {
        let passes = (cipher_bytes.len() / trial_size) - 1;

        let sum_distance = (0..passes).map(|index| {
            let slice_1 = &cipher_bytes[trial_size*index..trial_size*(index+1)];
            let slice_2 = &cipher_bytes[trial_size*(index+1)..trial_size*(index+2)];
            hamming::bit_distance(slice_1, slice_2)
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

        break_single_byte_key(&block).key
    }).collect()
}
