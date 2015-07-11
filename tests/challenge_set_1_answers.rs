pub mod set_1 {
    pub mod challenge_1 {
        pub static HEX_STRING: &'static str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        pub static BASE64_STRING: &'static str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    }

    pub mod challenge_2 {
        pub static STRING_1: &'static str = "1c0111001f010100061a024b53535009181c";
        pub static STRING_2: &'static str = "686974207468652062756c6c277320657965";
        pub static RESULT: &'static str = "746865206b696420646f6e277420706c6179";
    }

    pub mod challenge_3 {
        pub static HEX_STRING: &'static str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        pub static PLAINTEXT: &'static str = "Cooking MC's like a pound of bacon";
        pub static KEY: u8 = 0x58;
    }

    pub mod challenge_4 {
        pub static FILE_PATH: &'static str = "fixtures/4.txt";
        pub static PLAINTEXT: &'static str = "Now that the party is jumping\n";
        pub static KEY: u8 = 0x35;
        pub static LINE_NUMBER: usize = 170;
    }

    pub mod challenge_5 {
        pub static PLAINTEXT: &'static str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        pub static KEY: &'static str = "ICE";
        pub static CIPHER_STRING: &'static str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    }

    pub mod hamming_test {
        pub static STRING_1: &'static str = "this is a test";
        pub static STRING_2: &'static str = "wokka wokka!!!";
        pub static DISTANCE: usize = 37;
    }

    pub mod challenge_6 {
        pub static FILE_PATH: &'static str = "fixtures/6.txt";
        pub static KEY: &'static str = "Terminator X: Bring the noise";
    }
}
