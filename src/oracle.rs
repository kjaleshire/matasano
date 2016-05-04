use rand;
use rand::Rng;
use rand::distributions::{IndependentSample, Range};

use serialize::base64::FromBase64;

use aes;
use analyzer::Mode;
use utility::error::MatasanoError;

pub struct Oracle {
    pub block_size: usize,
    pub last_key: Vec<u8>,
    pub last_mode: Mode,
    pub rng: rand::ThreadRng,
}

impl Oracle {
    pub fn new() -> Self {
        Oracle{
            block_size: 16,
            last_key: Vec::with_capacity(0),
            last_mode: Mode::None,
            rng: rand::thread_rng(),
        }
    }

    pub fn generate_random_aes_key(&mut self) -> Vec<u8> {
        (0..self.block_size).map(|_| self.rng.gen()).collect()
    }

    pub fn randomly_mangled_encrypted_text(&mut self) -> Vec<u8> {
        let text_size = 3 * self.block_size;
        let random_byte: u8 = self.rng.gen();
        let prefix_size = Range::new(5, 11).ind_sample(&mut self.rng);
        let suffix_size = Range::new(5, 11).ind_sample(&mut self.rng);
        let vec_size = aes::padded_len(prefix_size + text_size + suffix_size, self.block_size);

        let mut mangled_text = Vec::with_capacity(vec_size);

        for _ in 0..prefix_size {
            mangled_text.push(self.rng.gen());
        }

        for _ in 0..text_size {
            mangled_text.push(random_byte);
        }

        for _ in 0..suffix_size {
            mangled_text.push(self.rng.gen());
        }

        let _ = aes::pkcs_pad_vec(&mut mangled_text, self.block_size);

        match self.rng.gen() {
            true => {
                self.last_mode = Mode::Cbc;
                let iv = vec![0; self.block_size];
                aes::encrypt_cbc_128_text(&mangled_text, &self.generate_random_aes_key(), &iv)
            },
            false => {
                self.last_mode = Mode::Ecb;
                aes::encrypt_ecb_128_text(&mangled_text, &self.generate_random_aes_key())
            }
        }
    }

    pub fn randomly_appended_encrypted_text(&mut self, plain_text: &[u8]) -> Result<Vec<u8>, MatasanoError> {
        let append_vec = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".from_base64()?;

        let vec_size = aes::padded_len(plain_text.len() + append_vec.len(), self.block_size);

        let mut mangled_text = Vec::with_capacity(vec_size);

        mangled_text.extend_from_slice(&plain_text);
        mangled_text.extend_from_slice(&append_vec);
        let _ = aes::pkcs_pad_vec(&mut mangled_text, self.block_size);

        self.last_key = self.generate_random_aes_key();
        self.last_mode = Mode::Ecb;
        Ok(aes::encrypt_ecb_128_text(&mangled_text, &self.last_key))
    }
}
