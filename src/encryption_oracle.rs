use rand;
use rand::{Rng, ThreadRng};
use rand::distributions::{IndependentSample, Range};

use set_2;

#[derive(Debug, PartialEq)]
pub enum EncryptionMode {
    Ecb,
    Cbc,
    None
}

pub struct Oracle {
    pub block_size: usize,
    pub last_mode: EncryptionMode,
    pub rng: rand::ThreadRng,
}

impl Oracle {
    pub fn new() -> Self {
        Oracle{
            block_size: 16,
            last_mode: EncryptionMode::None,
            rng: rand::thread_rng(),
        }
    }

    pub fn generate_random_aes_key(&mut self) -> Vec<u8> {
        (0..self.block_size).map(|_| self.rng.gen()).collect()
    }

    pub fn randomly_encrypted_text(&mut self) -> Vec<u8> {
        let text_size = 3 * self.block_size;
        let random_byte: u8 = self.rng.gen();
        let prefix_size = Range::new(5, 11).ind_sample(&mut self.rng);
        let suffix_size = Range::new(5, 11).ind_sample(&mut self.rng);
        let vec_size = set_2::padded_len(prefix_size + text_size + suffix_size, self.block_size);

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

        let _ = set_2::pkcs_pad_string(&mut mangled_text, self.block_size);

        match self.rng.gen() {
            true => {
                self.last_mode = EncryptionMode::Cbc;
                let iv = vec![0; self.block_size];
                set_2::encrypt_aes_cbc_text(&mangled_text, &self.generate_random_aes_key(), &iv)
            },
            false => {
                self.last_mode = EncryptionMode::Ecb;
                set_2::encrypt_aes_ebc_text(&mangled_text, &self.generate_random_aes_key())
            }
        }
    }
}
