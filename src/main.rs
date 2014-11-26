extern crate challenge_set_1;

#[allow(dead_code)]
fn main() {
    let decoded_state = challenge_set_1::challenge_4("/Users/kja/Desktop/4.txt");

    println!("Decoded string is `{}` on line {} with cipher 0x{:x}", decoded_state.string, decoded_state.line, decoded_state.cipher);
}
