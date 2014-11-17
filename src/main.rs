extern crate challenge_set_1;

#[allow(dead_code)]
fn main() {
    let hex_string = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let (cipher_char, decoded_string) = challenge_set_1::challenge_3(hex_string);

    println!("Decoded string is `{}` with cipher 0x{:x}", String::from_utf8(decoded_string).unwrap(), cipher_char);
}
