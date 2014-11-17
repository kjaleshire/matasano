extern crate challenge_set_1;

#[test]
fn challenge_test_1() {
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(challenge_set_1::challenge_1(hex_string.as_bytes()), base64_string.to_string());
}

#[test]
fn challenge_test_2() {
    let hex_string_1 = "1c0111001f010100061a024b53535009181c";
    let hex_string_2 = "686974207468652062756c6c277320657965";

    let result_string = "746865206b696420646f6e277420706c6179";

    assert_eq!(String::from_utf8(challenge_set_1::challenge_2(hex_string_1, hex_string_2)).unwrap(), result_string.to_string());
}

#[test]
fn challenge_test_3() {
    let hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let (cipher_char, decoded_string) = challenge_set_1::challenge_3(hex_string.as_bytes());

    assert_eq!(String::from_utf8(decoded_string).unwrap(), "Cooking MC's like a pound of bacon".to_string());
    assert_eq!(cipher_char, 0x58);
}
