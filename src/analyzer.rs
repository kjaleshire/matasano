use serialize::hex::FromHex;

use std::io::BufRead;

use utility::error::MatasanoError;

#[derive(Debug, PartialEq)]
pub enum Mode {
    Ecb,
    Cbc,
    None
}

pub fn detect_ecb_line<T>(cipher_lines: T) -> Result<usize, MatasanoError> where T: BufRead {
    for (line_number, line) in cipher_lines.lines().enumerate() {
        let line_bytes = line?.from_hex()?;

        match detect_encryption_mode(&line_bytes, 16) {
            Mode::Ecb => return Ok(line_number + 1),
            Mode::Cbc | Mode::None => {}
        }
    };

    Err(MatasanoError::Other("No match found in any lines"))
}

pub fn detect_encryption_mode(byte_slice: &[u8], block_size: usize) -> Mode {
    for (index, chunk) in byte_slice[..].chunks(block_size).enumerate() {
        if byte_slice[..].chunks(block_size).skip(index + 1).any(|other| chunk == other) {
            return Mode::Ecb;
        }
    }
    Mode::Cbc
}
