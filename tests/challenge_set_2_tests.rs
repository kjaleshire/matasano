extern crate matasano;
extern crate rand;
extern crate rustc_serialize as serialize;

use matasano::{file_util, set_1, set_2};
use matasano::encryption_oracle::Oracle;

use serialize::base64::FromBase64;

mod challenge_set_2_answers;

#[test]
fn challenge_9_test() {
    use challenge_set_2_answers::challenge_9::*;

    let mut byte_vec = Vec::from(ORIGINAL_STRING);

    let padding_len = set_2::pkcs_pad_string(&mut byte_vec, 20);

    assert_eq!(padding_len, 4);
    assert_eq!(&byte_vec[..], PADDED_STRING.as_bytes());
}

#[test]
fn challenge_10_test() {
    use challenge_set_2_answers::challenge_10::*;

    let cipher_bytes = file_util::dump_bytes(FILE_PATH).unwrap()[..].from_base64().unwrap();

    let decrypted_text = set_2::decrypt_aes_cbc_text(&cipher_bytes, KEY.as_bytes(), &IV).unwrap();

    assert_eq!(decrypted_text[..DECODED_FIRST_LINE.len()], DECODED_FIRST_LINE[..]);

    let encrypted_text = set_2::encrypt_aes_cbc_text(&decrypted_text.as_bytes(), KEY.as_bytes(), &IV);

    assert_eq!(encrypted_text, cipher_bytes);
}

#[test]
fn generate_random_key_test() {
    let mut oracle = Oracle::new();

    let key_1 = oracle.generate_random_aes_key();
    let key_2 = oracle.generate_random_aes_key();

    assert!(key_1 != key_2);
    assert_eq!(key_1.len(), 16);
    assert_eq!(key_2.len(), 16);
}

#[test]
fn encrypt_aes_ebc_text_test() {
    use challenge_set_2_answers::challenge_11::*;

    let cipher_bytes = file_util::dump_bytes(FILE_PATH).unwrap()[..].from_base64().unwrap();
    let decrypted_text = set_1::decrypt_aes_ecb_text(&cipher_bytes, KEY.as_bytes());

    assert_eq!(&decrypted_text[0..DECODED_FIRST_LINE.len()], DECODED_FIRST_LINE.as_bytes());

    let encrypted_text = set_2::encrypt_aes_ebc_text(&decrypted_text, KEY.as_bytes());

    assert_eq!(encrypted_text, cipher_bytes);
}

#[test]
fn challenge_11_test() {
    let mut oracle = Oracle::new();

    for _ in 0..21 {
        let encoded_bytes = oracle.randomly_encrypted_text();
        let detected_mode = set_2::detect_encryption_mode(&encoded_bytes);

        assert_eq!(detected_mode, oracle.last_mode);
    }
}
