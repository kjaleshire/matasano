#![feature(globs)]

extern crate matasano;

use matasano::set_1;
use matasano::hamming_distance;

mod challenge_set_1_answers;

#[test]
fn challenge_1_test() {
    use challenge_set_1_answers::set_1::challenge_1::*;

    assert_eq!(set_1::hex_chars_to_values_base64(HEX_STRING.as_bytes()).as_slice(), BASE64_STRING);
}

#[test]
fn challenge_2_test() {
    use challenge_set_1_answers::set_1::challenge_2::*;

    assert_eq!(set_1::string_xor(HEX_STRING_1, HEX_STRING_2).as_slice(), RESULT_STRING);
}

#[test]
fn challenge_3_test() {
    use challenge_set_1_answers::set_1::challenge_3::*;

    let decoded_state = set_1::break_single_char_cipher(HEX_STRING);

    assert_eq!(decoded_state.string.as_slice(), ANSWER);
    assert_eq!(decoded_state.cipher, CIPHER);
}

#[test]
fn challenge_4_test() {
    use challenge_set_1_answers::set_1::challenge_4::*;

    let decoded_state = set_1::break_multiline_file_cipher(FIXTURE_FILE);

    assert_eq!(decoded_state.string.as_slice(), DECODED_STRING);
    assert_eq!(decoded_state.cipher, CIPHER);
    assert_eq!(decoded_state.line, LINE);
}

#[test]
fn challenge_5_test() {
    use challenge_set_1_answers::set_1::challenge_5::*;

    let encoded_string = set_1::xor_repeating_key(START_STRING, CIPHER);

    assert_eq!(encoded_string.as_slice(), ENCODED_STRING);
}

#[test]
fn hamming_distance_test() {
    use challenge_set_1_answers::set_1::hamming_distance::*;

    assert_eq!(HAMMING_DISTANCE, hamming_distance::bit_distance(HAMMING_TEST_STRING_1, HAMMING_TEST_STRING_2));
}

#[test]
fn challenge_6_test() {
    use challenge_set_1_answers::set_1::challenge_6::*;

    set_1::challenge_6(FIXTURE_FILE);
}
