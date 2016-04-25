extern crate matasano;
extern crate rustc_serialize as serialize;

use matasano::set_1;
use matasano::file_util;
use matasano::hamming_util;

use serialize::hex::FromHex;
use serialize::base64::FromBase64;

mod challenge_set_1_answers;

#[test]
fn challenge_1_test() {
    use challenge_set_1_answers::set_1::challenge_1::*;

    let base64_string = &set_1::hex_decode_base64(HEX_STRING).unwrap()[..];

    assert_eq!(base64_string, BASE64_STRING);
}

#[test]
fn challenge_2_test() {
    use challenge_set_1_answers::set_1::challenge_2::*;

    let result = &set_1::string_xor(STRING_1, STRING_2).unwrap()[..];

    assert_eq!(result, RESULT);
}

#[test]
fn challenge_3_test() {
    use challenge_set_1_answers::set_1::challenge_3::*;

    let cipher_bytes = HEX_STRING.from_hex().unwrap();
    let decoded_state = set_1::break_single_line_byte_key(&cipher_bytes[..]);

    assert_eq!(&decoded_state.string[..], PLAINTEXT);
    assert_eq!(decoded_state.key, KEY);
}

#[test]
fn challenge_4_test() {
    use challenge_set_1_answers::set_1::challenge_4::*;

    let decoded_state = set_1::break_multiline_file_byte_key(FILE_PATH).unwrap();

    assert_eq!(&decoded_state.string[..], PLAINTEXT);
    assert_eq!(decoded_state.key, KEY);
    assert_eq!(decoded_state.line, LINE_NUMBER);
}

#[test]
fn challenge_5_test() {
    use challenge_set_1_answers::set_1::challenge_5::*;

    let cipher_string = &set_1::repeating_key_xor(PLAINTEXT, KEY)[..];

    assert_eq!(cipher_string, CIPHER_STRING);
}

#[test]
fn hamming_distance_test() {
    use challenge_set_1_answers::set_1::hamming_test::*;

    let distance = hamming_util::bit_distance(STRING_1.as_bytes(), STRING_2.as_bytes());

    assert_eq!(distance, DISTANCE);
}

#[test]
fn challenge_6_test() {
    use challenge_set_1_answers::set_1::challenge_6::*;

    let cipher_bytes = file_util::dump_bytes(FILE_PATH).unwrap()[..].from_base64().unwrap();
    let key = set_1::break_repeating_key_xor_string(&cipher_bytes[..]);

    assert_eq!(&key[..], KEY.as_bytes());
}

#[test]
fn challenge_7_test() {
    use challenge_set_1_answers::set_1::challenge_7::*;

    let cipher_bytes = file_util::dump_bytes(FILE_PATH).unwrap()[..].from_base64().unwrap();;
    let result = set_1::decrypt_aes_ecb_text(&cipher_bytes, KEY.as_bytes()).expect("Cipher error!");

    assert_eq!(&result[0..DECODED_FIRST_LINE.len()], DECODED_FIRST_LINE.as_bytes());
}

#[test]
fn challenge_8_test() {
    use challenge_set_1_answers::set_1::challenge_8::*;

    let line_number = set_1::detect_ecb_file_line(FILE_PATH).unwrap();

    assert_eq!(line_number, LINE_NUMBER);
}
