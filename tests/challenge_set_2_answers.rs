pub mod challenge_9 {
    pub static ORIGINAL_STRING: &'static str = "YELLOW SUBMARINE";
    pub static PADDED_STRING: &'static str = "YELLOW SUBMARINE\x04\x04\x04\x04";
}

pub mod challenge_10 {
    pub static DECODED_FIRST_LINE: &'static str = "I'm back and I'm ringin' the bell";
    pub static FILE_PATH: &'static str = "fixtures/10.txt";
    pub static IV: [u8; 16] = [0; 16];
    pub static KEY: &'static str = "YELLOW SUBMARINE";
}

pub mod challenge_11 {
    pub static FILE_PATH: &'static str = "fixtures/7.txt";
    pub static KEY: &'static str = "YELLOW SUBMARINE";
    pub static DECODED_FIRST_LINE: &'static str = "I'm back and I'm ringin' the bell";
}
