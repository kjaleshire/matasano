extern crate matasano;

use matasano::set_1;

mod challenge_set_1_answers;

#[test]
fn challenge_1_test() {
    use challenge_set_1_answers::challenge_1::*;

    let base64_string = set_1::hex_decode_base64(HEX_STRING).unwrap();

    assert_eq!(base64_string, BASE64_STRING);
}

#[test]
fn challenge_2_test() {
    use challenge_set_1_answers::challenge_2::*;

    let result = set_1::string_xor(STRING_1, STRING_2).expect("Challenge 2: could not XOR strings");

    assert_eq!(result, RESULT);
}

#[test]
fn challenge_3_test() {
    use challenge_set_1_answers::challenge_3::*;

    let decoded_state = set_1::break_single_byte_key_from_hex_string(HEX_STRING)
        .expect("Challenge 3: could not unhex string");

    assert_eq!(decoded_state.string, PLAINTEXT);
    assert_eq!(decoded_state.key, KEY);
}

#[test]
fn challenge_4_test() {
    use challenge_set_1_answers::challenge_4::*;

    let decoded_state =
        set_1::break_multiline_file_byte_key(FILE_PATH).expect("Challenge 4: could not read file");

    assert_eq!(decoded_state.string, PLAINTEXT);
    assert_eq!(decoded_state.key, KEY);
    assert_eq!(decoded_state.line, LINE_NUMBER);
}

#[test]
fn challenge_5_test() {
    use challenge_set_1_answers::challenge_5::*;

    let cipher_string = set_1::encode_with_repeating_key(PLAINTEXT, KEY);

    assert_eq!(cipher_string, CIPHER_STRING);
}

#[test]
fn hamming_distance_test() {
    use challenge_set_1_answers::hamming_test::*;

    let distance = set_1::strings_hamming_distance(STRING_1, STRING_2);

    assert_eq!(distance, DISTANCE);
}

#[test]
fn challenge_6_test() {
    use challenge_set_1_answers::challenge_6::*;

    let key =
        set_1::break_xor_file_repeating_key(FILE_PATH).expect("Challenge 6: could not read file");

    assert_eq!(key, Vec::from(KEY));
}

#[test]
fn challenge_7_test() {
    use challenge_set_1_answers::challenge_7::*;

    let decrypted_text =
        set_1::decrypt_aes_ecb_file(FILE_PATH, KEY).expect("Challenge 7: could not read file");

    assert_eq!(
        decrypted_text[0..DECODED_FIRST_LINE.len()],
        DECODED_FIRST_LINE[..]
    );
}

#[test]
fn challenge_8_test() {
    use challenge_set_1_answers::challenge_8::*;

    let line_number = set_1::detect_ecb_file_line(FILE_PATH).unwrap();

    assert_eq!(line_number, LINE_NUMBER);
}
