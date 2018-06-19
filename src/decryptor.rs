use hex;

use std::io::BufRead;
use std::str;

use analyzer;
use utility::english;
use utility::error::{Result, ResultExt};
use utility::hamming;

pub struct ByteKeyState {
    pub score: f32,
    pub key: u8,
    pub line: usize,
    pub string: String,
}

pub struct KeyState {
    pub distance: f32,
    pub size: usize,
}

impl Copy for KeyState {}
impl Clone for KeyState {
    fn clone(&self) -> KeyState {
        *self
    }
}

pub fn break_single_byte_key(cipher_bytes: &[u8]) -> ByteKeyState {
    let initial_state = ByteKeyState {
        score: 0.0,
        key: 0,
        line: 0,
        string: String::new(),
    };

    let mut decoded_vec = Vec::with_capacity(cipher_bytes.len());

    (0u8..255).fold(initial_state, |current_state, trial_key_byte| {
        decoded_vec.clear();

        for cipher_byte in cipher_bytes {
            decoded_vec.push(cipher_byte ^ trial_key_byte);
        }

        match str::from_utf8(&decoded_vec) {
            Ok(str_slice) => {
                let score = english::string_score(str_slice);

                match score > current_state.score {
                    true => ByteKeyState {
                        score: score,
                        key: trial_key_byte,
                        line: 0,
                        string: String::from(str_slice),
                    },
                    false => current_state,
                }
            }
            Err(_) => current_state,
        }
    })
}

pub fn break_lines_key<T>(cipher_lines: T) -> Result<ByteKeyState>
where
    T: BufRead,
{
    let initial_state = ByteKeyState {
        score: 0.0,
        key: 0x0,
        line: 0,
        string: String::new(),
    };

    cipher_lines.lines().enumerate().fold(
        Ok(initial_state),
        |state, (next_line_number, next_line_result)| {
            let next_line = next_line_result.chain_err(|| "could not unwrap next line")?;
            let current_state = state.chain_err(|| "could not get current state")?;
            let line = hex::decode(next_line).chain_err(|| "could not decode hex string")?;
            let mut trial_state = break_single_byte_key(&line);

            match trial_state.score > current_state.score {
                true => {
                    trial_state.line = next_line_number + 1;
                    Ok(trial_state)
                }
                false => Ok(current_state),
            }
        },
    )
}

pub fn break_repeating_key_xor(cipher_bytes: &[u8]) -> Vec<u8> {
    let initial_state = KeyState {
        distance: 9000.0,
        size: 0,
    };
    let min_key_size = 2;
    let max_key_size = 64;

    let key_size = (min_key_size..max_key_size)
        .fold(initial_state, |current_state, trial_size| {
            let passes = (cipher_bytes.len() / trial_size) - 1;

            let sum_distance = (0..passes)
                .map(|index| {
                    let slice_1 = &cipher_bytes[trial_size * index..trial_size * (index + 1)];
                    let slice_2 = &cipher_bytes[trial_size * (index + 1)..trial_size * (index + 2)];
                    hamming::bit_distance(slice_1, slice_2)
                })
                .fold(0, |a, s| a + s);

            let normalized_distance = sum_distance as f32 / (passes * trial_size) as f32;

            match normalized_distance < current_state.distance {
                true => KeyState {
                    size: trial_size,
                    distance: normalized_distance,
                },
                false => current_state,
            }
        })
        .size;

    let number_of_blocks = cipher_bytes.len() / key_size;

    let mut block = Vec::with_capacity(number_of_blocks);

    (0..key_size)
        .map(|size_index| {
            block.clear();

            for block_index in 0..number_of_blocks {
                block.push(cipher_bytes[block_index * key_size + size_index]);
            }

            break_single_byte_key(&block).key
        })
        .collect()
}

pub fn break_oracle_append_fn<F>(mut oracle_fn: &mut F) -> Result<Vec<u8>>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let block_size = analyzer::detect_oracle_block_size(&mut oracle_fn, 32)?;

    // The size of the message we're trying to decode
    let max_decoded_size = oracle_fn(&[0; 0])?.len();

    // The vec for holding our eventually decoded bytes
    let mut decoded_vec = Vec::with_capacity(max_decoded_size + block_size);
    // Pre-populate with block size - 1 number of A's, so we can examine the last
    // byte.
    decoded_vec.resize(block_size - 1, 0x65);

    // Iterate over each block in the message
    'block_iter: for block_index in 0..(max_decoded_size / block_size) {
        // Iterate over each byte in the given block
        for byte_index in 0..block_size {
            // The total byte length of the blocks we've already decoded
            let block_base = block_index * block_size;
            let new_byte;

            {
                let current_decoded_block = &decoded_vec[..block_size - byte_index - 1];
                let encoded_vec = oracle_fn(current_decoded_block)?;
                let prefix_block = &decoded_vec[block_base + byte_index..];
                let current_encrypted_block = &encoded_vec[block_base..block_base + block_size];

                match find_matching_byte_from_encrypted_block(
                    oracle_fn,
                    prefix_block,
                    current_encrypted_block,
                )? {
                    None => break 'block_iter,
                    // Found a match, push the newly decoded byte onto the decoded vec
                    Some(last_byte) => new_byte = last_byte,
                }
            }

            decoded_vec.push(new_byte);
        }
    }

    // return the decoded vec minus the prepended A's we started with
    Ok(decoded_vec.split_off(block_size - 1))
}

fn find_matching_byte_from_encrypted_block<F>(
    oracle_fn: &mut F,
    prefix_block: &[u8],
    current_encrypted_block: &[u8],
) -> Result<Option<u8>>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let mut trial_vec = Vec::with_capacity(prefix_block.len() + 1);

    trial_vec.extend_from_slice(prefix_block);
    trial_vec.push(0x65);

    for index in 0..u8::max_value() {
        trial_vec[prefix_block.len()] = index;
        let mut encoded_vec = oracle_fn(&trial_vec)?;
        encoded_vec.truncate(prefix_block.len() + 1);

        if encoded_vec == current_encrypted_block {
            match index {
                // `1` is the PKS 7 padding that indicates we're at the end of the message
                // And therefore done
                1 => return Ok(None),
                // Found a match, push the newly decoded byte onto the decoded vec
                last_byte => return Ok(Some(last_byte)),
            }
        }
    }

    bail!("No match found for block")
}

pub fn break_oracle_append_prepend_fn<F>(oracle_fn: &mut F) -> Result<Vec<u8>>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let block_size = 16;
    let plaintext = Vec::new();
    let (matching_blocks, prepend_vec, _) =
        find_matching_blocks(oracle_fn, &plaintext, block_size)?;

    // Here we craft a new oracle function that removes the randomly prepended string
    // and calls the original oracle function
    break_oracle_append_fn(&mut |plaintext| {
        // Craft a new plaintext that pads the random string to the next block boundary
        let mut new_plaintext = prepend_vec.clone();
        // Prepend this new plaintext to the original one
        new_plaintext.extend_from_slice(plaintext);
        // Once it's encrypted, we know we can safely strip off the necessary number of encrypted
        // blocks that represent both the random string and our prepended new plaintext
        match oracle_fn(&new_plaintext) {
            Ok(ref mut ciphertext) => Ok(ciphertext.split_off(matching_blocks * block_size)),
            err => err,
        }
    })
}

pub fn find_matching_blocks<F>(
    oracle_fn: &mut F,
    initial_plaintext: &Vec<u8>,
    block_size: usize,
) -> Result<(usize, Vec<u8>, Vec<u8>)>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let mut plaintext = initial_plaintext.clone();
    let mut first_ciphertext = oracle_fn(&plaintext)?;
    plaintext.insert(0, 0x65);
    let mut second_ciphertext = oracle_fn(&plaintext)?;

    let detect_matching_blocks = |vec1: &[u8], vec2: &[u8]| {
        let iter1 = vec1.chunks(block_size);
        let iter2 = vec2.chunks(block_size);
        iter1
            .zip(iter2)
            .filter(|(block1, block2)| block1 == block2)
            .count()
    };

    let matching_blocks = detect_matching_blocks(&first_ciphertext, &second_ciphertext) + 1;

    loop {
        first_ciphertext = second_ciphertext;
        plaintext.insert(0, 0x65);
        second_ciphertext = oracle_fn(&plaintext)?;
        if matching_blocks <= detect_matching_blocks(&first_ciphertext, &second_ciphertext) {
            let _ = plaintext.pop();
            break;
        }
    }

    Ok((matching_blocks, plaintext, first_ciphertext))
}
