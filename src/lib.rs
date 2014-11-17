#![crate_name = "challenge_set_1"]
#![crate_type = "lib"]
#![feature(slicing_syntax, if_let)]

extern crate serialize;
use serialize::base64::{Config,ToBase64,Standard};

use std::vec::Vec;

struct BitXorVec(Vec<u8>);

pub fn challenge_1(hex_string: &[u8]) -> String {
    let config = Config { char_set: Standard, pad: true, line_length: None};

    hex_slice_to_values_vec(hex_string)[].to_base64(config)
}

pub fn challenge_2(hex_string_1: &str, hex_string_2: &str) -> Vec<u8> {
    let string_1 = hex_slice_to_values_vec(hex_string_1.as_bytes());
    let string_2 = hex_slice_to_values_vec(hex_string_2.as_bytes());

    values_slice_to_hex_string((BitXorVec(string_1) ^ BitXorVec(string_2))[])
}

pub fn challenge_3(hex_string: &[u8]) -> (u8, Vec<u8>) {
    let mut current_score = 0.0f32;
    let value_string = hex_slice_to_values_vec(hex_string);

    range(0x0u8, 0xFFu8).fold((0x0u8, Vec::with_capacity(0)), |(current_cipher, current_decode), potential_cipher_key| {
        let next_decode = value_string.iter().map(|value_char| {
            *value_char ^ potential_cipher_key
        }).collect::<Vec<u8>>();
        // match String::from_utf8(next_decode.clone()) {
        //     Ok(next_decode_string) => println!("Current decoded string is {} with cipher {:x}", next_decode_string, potential_cipher_key),
        //     Err(_) => println!("Couldn't convert this one to UTF-8 using cipher {:x}", potential_cipher_key)
        // }
        match frequency_score(next_decode[]) {
            score if score > current_score => {
                current_score = score;
                // println!("{:x} is new selected cipher character with score {}", potential_cipher_key, score);
                (potential_cipher_key, next_decode)
            },
            _ => (current_cipher, current_decode)
        }
    })
}

fn frequency_score(decoded_string: &[u8]) -> f32 {
    decoded_string.iter().map(|score_char| {
        if score_char.is_ascii() {
            match score_char.to_ascii().to_uppercase().to_byte() {
                b'E' => 12.02,
                b'T' => 9.10,
                b'A' => 8.12,
                b'O' => 7.68,
                b'I' => 7.31,
                b'N' => 6.95,
                b'S' => 6.28,
                b'R' => 6.02,
                b'H' => 5.92,
                b'D' => 4.32,
                b'L' => 3.98,
                b'U' => 2.88,
                b'C' => 2.71,
                b'M' => 2.61,
                b'F' => 2.30,
                b'Y' => 2.11,
                b'W' => 2.09,
                b'G' => 2.03,
                b'P' => 1.82,
                b'B' => 1.49,
                b'V' => 1.11,
                b'K' => 0.69,
                b'X' => 0.17,
                b'Q' => 0.11,
                b'J' => 0.10,
                b'Z' => 0.07,
                b'\'' => 0.0,
                b'"' => 0.0,
                b' ' => 0.0,
                _ => -10.0
            }
        } else {
            -10.0
        }
    }).fold(0.0, |acc, score| acc + score )
}

fn hex_slice_to_values_vec(hex_string: &[u8]) -> Vec<u8> {
    let mut collection = Vec::with_capacity((hex_string.len() / 2) + 1);
    for (index, hex_char) in hex_string.iter().enumerate() {
        match index % 2 == 0 {
            true => collection.push(hex_char_to_value(*hex_char) << 4),
            false => {
                if let Some(partial_char) = collection.last_mut() {
                    *partial_char |= hex_char_to_value(*hex_char);
                }
            }
        }
    }
    collection
}

fn hex_char_to_value(hex_char: u8) -> u8 {
    match hex_char {
        x if x >= b'0' && x <= b'9' => x - b'0',
        x if x >= b'a' && x <= b'f' => x - b'a' + 10,
        x => x
    }
}

fn values_slice_to_hex_string(values_slice: &[u8]) -> Vec<u8> {
    let mut string = Vec::with_capacity(values_slice.len() * 2);
    for value_char in values_slice.iter() {
        let (first_char, second_char) = (*value_char >> 4, *value_char & 0xF);
        string.push(value_to_hex_char(first_char));
        string.push(value_to_hex_char(second_char));
    }
    string
}

fn value_to_hex_char(hex_char: u8) -> u8 {
    match hex_char {
        x if x <= 9 => x + b'0',
        x if x >= 10 && x <= 15 => x + b'a' - 10,
        x => x
    }
}

impl std::ops::BitXor<BitXorVec, Vec<u8>> for BitXorVec {
    fn bitxor(&self, other: &BitXorVec) -> Vec<u8> {
        let BitXorVec(ref inner_self) = *self;
        let BitXorVec(ref inner_other) = *other;
        inner_self.iter().zip(inner_other.iter()).map(|(item_1, item_2)|{
            *item_1 ^ *item_2
        }).collect()
    }
}
