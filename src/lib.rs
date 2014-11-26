#![crate_name = "challenge_set_1"]
#![crate_type = "lib"]
#![feature(slicing_syntax, if_let)]

extern crate serialize;
use serialize::base64::{Config,ToBase64,Standard};

use std::vec::Vec;
use std::io::fs::File;
use std::io::BufferedReader;

struct BitXorVec(Vec<u8>);

pub struct DecodeState {
    pub score: uint,
    pub cipher: u8,
    pub line: uint,
    pub string: String
}

impl std::ops::BitXor<BitXorVec, Vec<u8>> for BitXorVec {
    fn bitxor(&self, other: &BitXorVec) -> Vec<u8> {
        let &BitXorVec(ref inner_self) = self;
        let &BitXorVec(ref inner_other) = other;

        inner_self.iter().zip(inner_other.iter()).map(|(&item_1, &item_2)|{
            item_1 ^ item_2
        }).collect()
    }
}

pub fn challenge_1(hex_string: &[u8]) -> String {
    hex_slice_to_values_vec(hex_string)[].to_base64(Config { char_set: Standard, pad: true, line_length: None})
}

pub fn challenge_2(hex_string_1: &str, hex_string_2: &str) -> String {
    let string_1 = hex_slice_to_values_vec(hex_string_1.as_bytes());
    let string_2 = hex_slice_to_values_vec(hex_string_2.as_bytes());

    values_slice_to_hex_string((BitXorVec(string_1) ^ BitXorVec(string_2))[])
}

pub fn challenge_3(hex_string: &str) -> DecodeState {
    let initial_state = DecodeState{ score: 0, cipher: 0x0, line: 0, string: String::with_capacity(0) };

    range(0x0u8, 0xFFu8).fold(initial_state, |current_state, next_cipher_key| {
        let decoded_vec = hex_slice_to_values_vec(hex_string.as_bytes()).iter().map(|&value_char| {
            value_char ^ next_cipher_key
        }).collect();
        match String::from_utf8(decoded_vec) {
            Ok(new_decode) => {
                // println!("Current decoded string is `{}` with cipher 0x{:x}", new_decode, current_state.cipher)
                match english_text_score(new_decode[]) {
                    next_score if next_score > current_state.score  => {
                        // println!("0x{:x} is new selected cipher character with score {}", next_cipher_key, next_score);
                        DecodeState{ score: next_score, cipher: next_cipher_key, line: 0, string: new_decode }
                    },
                    _ => current_state
                }
            },
            Err(_) => {
                // println!("Couldn't convert string to UTF-8 using cipher 0x{:x}", next_cipher_key)
                current_state
            }
        }
    })
}

pub fn challenge_4(file_path: &str) -> DecodeState {
    let mut file = BufferedReader::new(File::open(&Path::new(file_path)));
    let initial_state = DecodeState{ score: 0, cipher: 0x0, line: 0, string: String::with_capacity(0) };

    file.lines().enumerate().fold(initial_state, |current_state, (next_line_number, next_line)| {
        let mut byte_string = next_line.ok().unwrap();
        match byte_string.as_bytes().last() {
            Some(&last_char) => if last_char == b'\n' { byte_string.pop(); },
            None => {}
        }
        match challenge_3(byte_string.as_slice()) {
            DecodeState{score, cipher, line: _, ref string} if score > current_state.score => {
                DecodeState{ score: score, cipher: cipher, line: next_line_number, string: string.clone() }
            },
            _ => current_state
        }
    })
}

pub fn challenge_5(text_string: &str, cipher_key: &str) -> String {
    let cipher_iter = cipher_key.as_bytes().iter().cycle();
    let encoded_vec = text_string.as_bytes().iter().zip(cipher_iter).map(|(&byte_char, &cipher_char)| {
        byte_char ^ cipher_char
    }).collect::<Vec<u8>>();
    values_slice_to_hex_string(encoded_vec[])
}

// Quite hacky, but will do as a weekend solution. Something like Markov chains would be a better
// solution. Ragel state machines anyone?
fn english_text_score(decoded_string: &str) -> uint {
    decoded_string.chars().map(|score_char| {
        match score_char {
            x if x >= 'A' && x <= 'Z' => 1,
            x if x >= 'a' && x <= 'z' => 1,
            x if x >= '0' && x <= '9' => 1,
            ' ' => 1,
            '-' => 1,
            '\'' => 1,
            '\n' => 1,
            '/' => 1,
            ',' => 1,
            '.' => 1,
            '?' => 1,
            '!' => 1,
            _ => 0
        }
    }).fold(0, |acc, score| acc + score )
}

fn hex_slice_to_values_vec(hex_string: &[u8]) -> Vec<u8> {
    if hex_string.len() % 2 == 1 {
        panic!("Must be even-length byte array. Last char `{}`", hex_string.last().unwrap());
    }
    hex_string.iter().enumerate().filter(|&(index, _)| {
        index % 2 == 0
    }).zip(hex_string.iter().enumerate().filter(|&(index, _)| {
        index % 2 == 1
    })).map(|((_, &left_char), (_, &right_char))| {
        hex_char_to_value(right_char) | hex_char_to_value(left_char) << 4
    }).collect()
}

fn hex_char_to_value(hex_char: u8) -> u8 {
    match hex_char {
        x if x >= b'0' && x <= b'9' => x - b'0',
        x if x >= b'a' && x <= b'f' => x - b'a' + 10,
        x => x
    }
}

fn values_slice_to_hex_string(values_slice: &[u8]) -> String {
    let decoded_vec = values_slice.iter().flat_map(|&value_char| {
        (vec![value_to_hex_char(value_char >> 4), value_to_hex_char(value_char & 0xF)]).into_iter()
    }).collect();
    match String::from_utf8(decoded_vec) {
        Ok(new_decode) => new_decode,
        Err(vec) => panic!("Vector {} is not a valid UTF-8 string", vec)
    }
}

fn value_to_hex_char(hex_char: u8) -> u8 {
    match hex_char {
        x if x <= 9 => x + b'0',
        x if x >= 10 && x <= 15 => x + b'a' - 10,
        x => x
    }
}
