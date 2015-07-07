use serialize::base64::{Config,ToBase64,FromBase64,Standard,Newline};
use serialize::hex::{FromHex, ToHex};

use std::vec::Vec;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::io::BufReader;
use std::io::BufRead;
use std::cmp::Ordering::Equal;

use english_text_util;
use hamming_distance;

pub struct DecodeState {
    pub score: f32,
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

// Challenge 1
pub fn hex_decode_string_base64(hex_string: &str) -> String {
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
pub fn break_single_char_cipher(hex_string: &str) -> DecodeState {
    let initial_state = DecodeState{ score: 0.0, cipher: 0x0, line: 0, string: String::with_capacity(0) };

    (0x0u8..0xFFu8).fold(initial_state, |current_state, next_cipher_key| {
        let decoded_vec = hex_string.from_hex().unwrap().iter().map(|&value_char| {
            value_char ^ next_cipher_key
        }).collect();
        match String::from_utf8(decoded_vec) {
            Ok(new_decode) => {
                match english_text_util::string_score(&new_decode[..]) {
                    next_score if next_score > current_state.score  => {
                        DecodeState{ score: next_score, cipher: next_cipher_key, line: 0, string: new_decode }
                    },
                    _ => current_state
                }
            },
            _ => current_state
        }
    })
}

// Challenge 4
pub fn break_multiline_file_cipher(file_path: &str) -> DecodeState {
    let initial_state = DecodeState{ score: 0.0, cipher: 0x0, line: 0, string: String::with_capacity(0) };
    
    let file = BufReader::new(File::open(&Path::new(file_path)).unwrap());

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
    text_string.as_bytes().iter().zip(cipher_iter).map(|(&byte_char, &cipher_char)| {
        byte_char ^ cipher_char
    }).collect::<Vec<u8>>()[..].to_hex()
}

// Challenge 6
pub fn challenge_6(file_path: &str) -> DecodeState {
    let mut file = File::open(&Path::new(file_path)).unwrap();
    let mut raw_contents = Vec::new();
    file.read_to_end(&mut raw_contents);
    let contents = String::from_utf8(raw_contents[..].from_base64().unwrap()).unwrap();

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

    DecodeState{ score: 0.0, cipher: 0, line: 0, string: String::new() }
}
