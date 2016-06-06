use rand;
use rand::Rng;
use rand::distributions::{IndependentSample, Range};

use serialize::base64::FromBase64;

use aes;
use analyzer::Mode;
use utility::error::MatasanoError;

pub struct Oracle {
    pub append_vec: Option<Vec<u8>>,
    pub block_size: usize,
    pub key: Vec<u8>,
    pub last_mode: Mode,
    pub rng: rand::ThreadRng,
}

impl Oracle {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key = Self::generate_random_aes_key(&mut rng, 16);

        Oracle {
            append_vec: None,
            block_size: 16,
            key: key,
            last_mode: Mode::None,
            rng: rng,
        }
    }

    pub fn new_with_base64_append_str(append_str: &str) -> Result<Self, MatasanoError> {
        let mut rng = rand::thread_rng();
        let key = Self::generate_random_aes_key(&mut rng, 16);

        Ok(Oracle {
            append_vec: Some(append_str.from_base64()?),
            block_size: 16,
            key: key,
            last_mode: Mode::None,
            rng: rng,
        })
    }

    fn generate_random_aes_key(rng: &mut rand::ThreadRng, block_size: usize) -> Vec<u8> {
        (0..block_size).map(|_| rng.gen()).collect()
    }

    pub fn set_random_aes_key(&mut self) -> Vec<u8> {
        Self::generate_random_aes_key(&mut self.rng, self.block_size)
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

        mangled_text.resize(prefix_size + text_size, random_byte);

        for _ in 0..suffix_size {
            mangled_text.push(self.rng.gen());
        }

        let _ = aes::pkcs7_pad_vec(&mut mangled_text, self.block_size);

        match self.rng.gen() {
            true => {
                self.last_mode = Mode::Cbc;
                let iv = vec![0; self.block_size];
                aes::encrypt_cbc_128_text(&mangled_text, &self.key, &iv)
            }
            false => {
                self.last_mode = Mode::Ecb;
                aes::encrypt_ecb_128_text(&mangled_text, &self.key)
            }
        }
    }

    pub fn randomly_append_and_encrypt_text<'a>(&mut self,
                                                plain_text: &'a [u8])
                                                -> Result<Vec<u8>, MatasanoError> {
        let mut mangled_text: Vec<u8>;

        {
            let append_vec = match self.append_vec {
                Some(ref vec) => vec,
                None => {
                    return Err(MatasanoError::Other("Must set the append vec before using this \
                                                     method"))
                }
            };

            let vec_size = aes::padded_len(plain_text.len() + append_vec.len(), self.block_size);

            mangled_text = Vec::with_capacity(vec_size);

            mangled_text.extend_from_slice(&plain_text);
            mangled_text.extend_from_slice(&append_vec);
        }

        let _ = aes::pkcs7_pad_vec(&mut mangled_text, self.block_size);

        self.last_mode = Mode::Ecb;

        Ok(aes::encrypt_ecb_128_text(&mangled_text, &self.key))
    }
}
