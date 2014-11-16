#![crate_name = "challenge_set_1"]
#![crate_type = "lib"]
#![feature(slicing_syntax, if_let)]

extern crate serialize;
use serialize::base64::{Config,ToBase64,Standard};

use std::vec::Vec;

struct BitXorVec(Vec<u8>);

pub fn challenge_1(hex_string: &str) -> (String) {
    let config = Config { char_set: Standard, pad: true, line_length: None};

    hex_string_to_values(hex_string.as_bytes())[].to_base64(config)
}

pub fn challenge_2(hex_string_1: &str, hex_string_2: &str) -> String {
    let string_1 = hex_string_to_values(hex_string_1.as_bytes());
    let string_2 = hex_string_to_values(hex_string_2.as_bytes());

    values_to_hex_string((BitXorVec(string_1) ^ BitXorVec(string_2))[])
}

pub fn challenge_3(hex_string: &str) -> (String, u8) {
    let foo = b"ETAOINSHRDLU";

    for hex_value in range(0x0u, 0xAu) {

    }
}

fn hex_string_to_values(hex_string: &[u8]) -> Vec<u8> {
    let mut collection = Vec::with_capacity((hex_string.len() / 2) + 1);
    for (index, hex_char) in hex_string.iter().enumerate() {
        match index % 2 == 0 {
            true => { collection.push(hex_char_to_value(*hex_char) << 4); }
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

fn values_to_hex_string(hex_string: &[u8]) -> String {
    let mut string = String::with_capacity(hex_string.len() * 2);
    for hex_char in hex_string.iter() {
        let (first_char, second_char) = (*hex_char >> 4, *hex_char & 0xF);
        string.push(value_to_hex_char(first_char));
        string.push(value_to_hex_char(second_char));
    }
    string
}

fn value_to_hex_char(hex_char: u8) -> char {
    match hex_char {
        x if x <= 9 => (x + b'0') as char,
        x if x >= 10 && x <= 15 => (x + b'a' - 10) as char,
        x => x as char
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
