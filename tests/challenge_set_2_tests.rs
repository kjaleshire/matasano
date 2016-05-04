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
