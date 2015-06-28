use serialize::base64::{Config,ToBase64,FromBase64,Standard,Newline};

use std::vec::Vec;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::io::BufReader;
use std::io::BufRead;
use std::ops::BitXor;
use std::cmp::Ordering::Equal;

use hex_util;
use english_text_util;
use hamming_distance;

struct BitXorVec(Vec<u8>);

pub struct DecodeState {
    pub score: usize,
    pub cipher: u8,
    pub line: usize,
    pub string: String
}

#[derive(Debug)]
pub struct KeyScore {
    pub key_size: usize,
    pub score: f32
}

impl Copy for KeyScore {}
impl Clone for KeyScore {
    fn clone(&self) -> KeyScore {
        *self
    }
}

impl BitXor for BitXorVec {
    type Output = Vec<u8>;

    fn bitxor(self, other: BitXorVec) -> Vec<u8> {
        let BitXorVec(ref inner_self) = self;
        let BitXorVec(ref inner_other) = other;

        inner_self.iter().zip(inner_other.iter()).map( |(&item_1, &item_2)|
            item_1 ^ item_2
        ).collect()
    }
}

// Challenge 1
pub fn hex_decode_string_base64(hex_string: &[u8]) -> String {
    hex_util::hex_decode_string(hex_string).to_base64(Config { char_set: Standard, newline: Newline::LF, pad: true, line_length: None })
}

// Challenge 2
pub fn string_xor(hex_string_1: &str, hex_string_2: &str) -> String {
    let string_1 = hex_util::hex_decode_string(hex_string_1.as_bytes());
    let string_2 = hex_util::hex_decode_string(hex_string_2.as_bytes());

    let value_vec = hex_util::hex_encode_bytes_to_string(&(BitXorVec(string_1) ^ BitXorVec(string_2))[..]);

    match String::from_utf8(value_vec) {
        Ok(value_string) => value_string,
        Err(vec) => panic!("Vector {} is not a valid UTF-8 string", vec)
    }
}

// Challenge 3
pub fn break_single_char_cipher(hex_string: &str) -> DecodeState {
    let initial_state = DecodeState{ score: 0, cipher: 0x0, line: 0, string: String::with_capacity(0) };

    (0x0u8..0xFFu8).fold(initial_state, |current_state, next_cipher_key| {
        let decoded_vec = hex_util::hex_decode_string(hex_string.as_bytes()).iter().map(|&value_char| {
            value_char ^ next_cipher_key
        }).collect();
        match String::from_utf8(decoded_vec) {
            Ok(new_decode) => {
                // println!("Current decoded string is `{}` with cipher 0x{:x}", new_decode, current_state.cipher)
                match english_text_util::character_score(&new_decode[..]) {
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

// Challenge 4
pub fn break_multiline_file_cipher(file_path: &str) -> DecodeState {
    let file = BufReader::new(File::open(&Path::new(file_path)).unwrap());
    let initial_state = DecodeState{ score: 0, cipher: 0x0, line: 0, string: String::with_capacity(0) };

    file.lines().enumerate().fold(initial_state, |current_state, (next_line_number, next_line)| {
        let mut byte_string = next_line.unwrap();
        match byte_string.as_bytes().last() {
            Some(&last_char) => if last_char == b'\n' { byte_string.pop(); },
            None => {}
        }
        match break_single_char_cipher(&byte_string[..]) {
            DecodeState{ score, cipher, line: _, ref string } if score > current_state.score => {
                DecodeState{ score: score, cipher: cipher, line: next_line_number, string: string.clone() }
            },
            _ => current_state
        }
    })
}

// Challenge 5
pub fn xor_repeating_key(text_string: &str, cipher_key: &str) -> String {
    let cipher_iter = cipher_key.as_bytes().iter().cycle();
    let encoded_vec = text_string.as_bytes().iter().zip(cipher_iter).map(|(&byte_char, &cipher_char)| {
        byte_char ^ cipher_char
    }).collect::<Vec<u8>>();

    match String::from_utf8(hex_util::hex_encode_bytes_to_string(&encoded_vec[..])) {
        Ok(value_string) => value_string,
        Err(vector) => panic!("Vector {} is not a valid UTF-8 string", vector)
    }
}

// Challenge 6
pub fn challenge_6(file_path: &str) -> DecodeState {
    let mut file = File::open(&Path::new(file_path)).unwrap();
    let mut raw_contents = Vec::new();
    file.read_to_end(&mut raw_contents);
    let contents = match String::from_utf8(raw_contents[..].from_base64().unwrap()) {
        Ok(value_string) => value_string,
        Err(vector) => panic!("Vector {} is not a valid UTF-8 string", vector)
    };

    let mut keys_scores = (2..80).map( |key_size| {
        let n_slices = contents.len() / (key_size * 2);
        // println!("string length: {}. key_size: {}. n_slices: {}.", contents.len(), key_size, n_slices);
        let average_distance = (0..n_slices).map(|mut index| {
            index = index * 4;
            // println!("indexes: {}..{}, {}..{}", index, index + key_size, index + key_size, index + (key_size * 2));
            let slice_1 = &contents[index..index+key_size];
            let slice_2 = &contents[index+key_size..index+(key_size*2)];
            hamming_distance::bit_distance(slice_1, slice_2) as f32 / key_size as f32
        }).fold(0.0, |accumulator, distance| accumulator + distance ) / n_slices as f32;
        // println!("distance: {}", average_distance);
        KeyScore { key_size: key_size, score: average_distance }
    }).collect::<Vec<KeyScore>>();

    keys_scores.sort_by( |first, second| first.score.partial_cmp(&second.score).unwrap_or(Equal) );

    let key_score = keys_scores.first().unwrap();

    let n_blocks = contents.len() / key_score.key_size + 1;

    let blocks = (0..n_blocks).map(|slice| {
        contents.bytes().skip(slice*key_score.key_size).take(key_score.key_size).collect()
        // contents[slice*key_score.key_size..(slice+1)*key_score.key_size]
    }).collect::<Vec<Vec<u8>>>();

    // for block in blocks.iter() {
    //     println!("block: {:?}", block);
    // }

    // for index in range(0, key_score.key_size) {

    // }

    DecodeState{ score: 0, cipher: 0, line: 0, string: String::new() }
}
