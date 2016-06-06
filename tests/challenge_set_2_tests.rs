extern crate matasano;

use matasano::set_2;

mod challenge_set_2_answers;

#[test]
fn challenge_9_test() {
    use challenge_set_2_answers::challenge_9::*;

    let padded_string = set_2::pkcs_pad_string(ORIGINAL_STRING, 20);

    assert_eq!(padded_string.len(), ORIGINAL_STRING.len() + 4);
    assert_eq!(padded_string.as_bytes(), PADDED_STRING.as_bytes());
}

#[test]
fn challenge_10_test() {
    use challenge_set_2_answers::challenge_10::*;

    let (decrypted_string, cipher_bytes) = set_2::decrypt_encrypt_aes_cbc_file(FILE_PATH, &IV, KEY).unwrap();

    assert_eq!(decrypted_string[..DECODED_FIRST_LINE.len()], DECODED_FIRST_LINE[..]);

    let encrypted_vec = set_2::encrypt_aes_cbc_text(&decrypted_string, &IV, KEY);

    assert_eq!(encrypted_vec, cipher_bytes);
}

#[test]
fn generate_random_key_test() {
    let (key_1, key_2) = set_2::oracle_generate_key_pair();

    assert!(key_1 != key_2);
    assert_eq!(key_1.len(), 16);
    assert_eq!(key_2.len(), 16);
}

#[test]
fn encrypt_aes_ecb_text_test() {
    use challenge_set_2_answers::challenge_11::*;

    let (decrypted_text, cipher_bytes) = set_2::decrypt_encrypt_aes_ecb_file(FILE_PATH, KEY).unwrap();

    assert_eq!(&decrypted_text[0..DECODED_FIRST_LINE.len()], DECODED_FIRST_LINE);

    let encrypted_text = set_2::encrypt_aes_ecb_text(&decrypted_text, KEY);

    assert_eq!(encrypted_text, cipher_bytes);
}

#[test]
fn challenge_11_test() {
    for _ in 0..21 {
        let (detected_mode, last_mode) = set_2::oracle_encrypt_and_guess();

        assert_eq!(detected_mode, last_mode);
    }
}

#[test]
fn detect_block_size() {
    use challenge_set_2_answers::challenge_12::*;

    let block_size = set_2::detect_oracle_block_size(APPEND_STR, 32).expect("Challenge 12: could not detect block size");

    assert_eq!(block_size, 16);
}

#[test]
fn detect_using_ecb() {
    use challenge_set_2_answers::challenge_12::*;

    let (mode, expected_mode) = set_2::detect_oracle_mode(APPEND_STR).expect("Challenge 12: could not detect mode");

    assert_eq!(mode, expected_mode);
}

#[test]
#[ignore]
fn challenge_12_test() {
    use challenge_set_2_answers::challenge_12::*;

    let decodec_str = set_2::decrypt_append_str(APPEND_STR).expect("Challenge 12: could not decrypt appended string");

    assert_eq!(EXPECTED_STR, &decodec_str[..]);
}

#[test]
fn deserialize_profile() {
    use challenge_set_2_answers::challenge_13::*;

    let object = set_2::deserialize_profile(ENCODED_PROFILE);
    let email = object.get("email").expect("Challenge 13: email not set in hash");

    assert_eq!(PROPER_EMAIL, email);
}

#[test]
fn serialized_profile_for() {
    use challenge_set_2_answers::challenge_13::*;

    let encoded_profile = set_2::serialized_profile_for(PROPER_EMAIL);

    assert_eq!(ENCODED_PROFILE, encoded_profile);
}

#[test]
fn malicious_serialized_profile_for() {
    use challenge_set_2_answers::challenge_13::*;

    let encoded_profile = set_2::serialized_profile_for(MALICIOUS_EMAIL);

    assert_eq!(SANITIZED_EMAIL, encoded_profile);
}
