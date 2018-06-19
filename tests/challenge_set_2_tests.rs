extern crate matasano;

use matasano::set_2;

mod challenge_set_2_answers;

#[test]
fn challenge_9_test() {
    use challenge_set_2_answers::challenge_9::{ORIGINAL_STRING, PADDED_STRING};

    let padded_string = set_2::pkcs_pad_string(ORIGINAL_STRING, 20).expect("could not pad string");

    assert_eq!(padded_string.len(), ORIGINAL_STRING.len() + 4);
    assert_eq!(padded_string.as_bytes(), PADDED_STRING.as_bytes());
}

#[test]
fn challenge_10_test() {
    use challenge_set_2_answers::challenge_10::{DECODED_FIRST_LINE, FILE_PATH, IV, KEY};

    let (plaintext_string, ciphertext_bytes) =
        set_2::decrypt_encrypted_aes_cbc_file(FILE_PATH, KEY, &IV)
            .expect("Challenge 10: Could not decrypt/encrypt file");

    assert_eq!(
        plaintext_string[..DECODED_FIRST_LINE.len()],
        DECODED_FIRST_LINE[..]
    );

    let encrypted_vec =
        set_2::encrypt_aes_cbc_text(&plaintext_string, KEY, &IV).expect("could not encrypt text");

    assert_eq!(encrypted_vec, ciphertext_bytes);
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
    use challenge_set_2_answers::challenge_11::{DECODED_FIRST_LINE, FILE_PATH, KEY};

    let (decrypted_text, ciphertext_bytes) = set_2::decrypt_encrypt_aes_ecb_file(FILE_PATH, KEY)
        .expect("Challenge 10: Could not decrypt/encrypt file");

    assert_eq!(
        &decrypted_text[0..DECODED_FIRST_LINE.len()],
        DECODED_FIRST_LINE
    );

    let encrypted_text =
        set_2::encrypt_aes_ecb_text(&decrypted_text, KEY).expect("could not encrypt text");

    assert_eq!(encrypted_text, ciphertext_bytes);
}

#[test]
fn challenge_11_test() {
    for _ in 0..21 {
        let (detected_mode, last_mode) =
            set_2::oracle_encrypt_and_guess().expect("could not guess mode");

        assert_eq!(detected_mode, last_mode);
    }
}

#[test]
fn detect_block_size() {
    use challenge_set_2_answers::challenge_12::APPEND_STR;

    let block_size = set_2::detect_oracle_block_size(APPEND_STR, 32)
        .expect("Challenge 12: could not detect block size");

    assert_eq!(block_size, 16);
}

#[test]
fn detect_using_ecb() {
    use challenge_set_2_answers::challenge_12::APPEND_STR;

    let (mode, expected_mode) =
        set_2::detect_oracle_mode(APPEND_STR).expect("Challenge 12: could not detect mode");

    assert_eq!(mode, expected_mode);
}

#[test]
fn challenge_12_test() {
    use challenge_set_2_answers::challenge_12::{APPEND_STR, EXPECTED_STR};

    let decodec_str = set_2::decrypt_append_str(APPEND_STR)
        .expect("Challenge 12: could not decrypt appended string");

    assert_eq!(EXPECTED_STR, &decodec_str[..]);
}

#[test]
fn deserialize_cookie() {
    use challenge_set_2_answers::challenge_13::{DESERIALIZED_COOKIE, SERIALIZED_COOKIE};

    let mut hashmap =
        set_2::deserialize_cookie(SERIALIZED_COOKIE).expect("could not deserialize cookie");

    for (key, value) in DESERIALIZED_COOKIE.iter() {
        assert_eq!(Some(String::from(*value)), hashmap.remove(*key));
    }

    assert_eq!(hashmap.len(), 0);
}

#[test]
fn deserialize_profile() {
    use challenge_set_2_answers::challenge_13::{PROPER_EMAIL, SERIALIZED_PROFILE};

    let object =
        set_2::deserialize_cookie(SERIALIZED_PROFILE).expect("could not deserialize cookie");
    let email = object
        .get("email")
        .expect("Challenge 13: email not set in hash");

    assert_eq!(&PROPER_EMAIL, email);
}

#[test]
fn serialized_profile_for() {
    use challenge_set_2_answers::challenge_13::{PROPER_EMAIL, SERIALIZED_PROFILE};

    let encoded_profile = set_2::serialized_profile_for(PROPER_EMAIL);

    assert_eq!(SERIALIZED_PROFILE, encoded_profile);
}

#[test]
fn malicious_serialized_profile_for() {
    use challenge_set_2_answers::challenge_13::{MALICIOUS_EMAIL, SANITIZED_SERIALIZED_COOKIE};

    let encoded_profile = set_2::serialized_profile_for(MALICIOUS_EMAIL);

    assert_eq!(SANITIZED_SERIALIZED_COOKIE, encoded_profile);
}

#[test]
fn encrypt_decrypt_profile() {
    use challenge_set_2_answers::challenge_13::PROPER_EMAIL;

    let cookie = set_2::create_cookie();

    let encrypted_profile =
        set_2::encrypted_profile_for(&cookie, PROPER_EMAIL).expect("could not encrypt profile");
    let profile = set_2::decrypted_profile_from(&cookie, &encrypted_profile)
        .expect("could not decrypt profile");

    assert_eq!(PROPER_EMAIL, profile.email);
    assert_eq!(10, profile.uid);
    assert_eq!("user", &profile.role[0..4]);
}

#[test]
fn challenge_13_test() {
    let cookie = set_2::create_cookie();

    let malicious_encrypted_profile =
        set_2::craft_encrypted_admin_profile(&cookie).expect("could not craft admin profile");

    let profile = set_2::decrypted_profile_from(&cookie, &malicious_encrypted_profile)
        .expect("could not decrypt profile");

    assert_eq!("admin", &profile.role[0..5]);
}

#[test]
fn challenge_14_test() {
    use challenge_set_2_answers::challenge_14::{APPEND_STR, EXPECTED_STR};

    let decodec_str = set_2::decrypt_append_str_with_random_prepend(APPEND_STR)
        .expect("Challenge 14: could not decrypt appended string");

    assert_eq!(EXPECTED_STR, &decodec_str[..]);
}

#[test]
fn check_invalid_pkcs7_1() {
    use challenge_set_2_answers::challenge_15::INVALID_PKCS7_PLAINTEXT_1;

    if let Err(result) = set_2::strip_pkcs7_padding(INVALID_PKCS7_PLAINTEXT_1) {
        assert_eq!("Invalid padding detected", result.description());
    } else {
        panic!("result was not an error");
    }
}

#[test]
fn check_invalid_pkcs7_2() {
    use challenge_set_2_answers::challenge_15::INVALID_PKCS7_PLAINTEXT_2;

    if let Err(result) = set_2::strip_pkcs7_padding(INVALID_PKCS7_PLAINTEXT_2) {
        assert_eq!("Invalid padding detected", result.description());
    } else {
        panic!("result was not an error");
    }
}

#[test]
fn challenge_15_test() {
    use challenge_set_2_answers::challenge_15::{VALID_PKCS7_PLAINTEXT, STRIPPED_PLAINTEXT};

    let result =
        set_2::strip_pkcs7_padding(VALID_PKCS7_PLAINTEXT).expect("could not strip padding");

    assert_eq!(STRIPPED_PLAINTEXT, result);
}
