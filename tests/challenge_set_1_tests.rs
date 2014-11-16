extern crate challenge_set_1;

#[test]
fn challenge_test_1() {
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(challenge_set_1::challenge_1(hex_string)[], base64_string);
}

#[test]
fn challenge_test_2() {
    let hex_string_1 = "1c0111001f010100061a024b53535009181c";
    let hex_string_2 = "686974207468652062756c6c277320657965";

    let result_string = "746865206b696420646f6e277420706c6179";

    assert_eq!(challenge_set_1::challenge_2(hex_string_1, hex_string_2)[], result_string);
}

#[test]
fn challenge_test_3() {

}
