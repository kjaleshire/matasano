use std::fs::File;
use std::io::{BufRead, BufReader, Lines, Read};

use error::MatasanoError;

pub fn lines_iterator(path: &str) -> Result<Lines<BufReader<File>>, MatasanoError> {
    Ok(BufReader::new(File::open(path)?).lines())
}

pub fn dump_bytes<'a>(path: &'a str) -> Result<Vec<u8>, MatasanoError> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len() as usize;

    let mut raw_bytes = Vec::with_capacity(size);
    let read_size = file.read_to_end(&mut raw_bytes)?;

    match read_size == size {
        true => Ok(raw_bytes),
        false => Err(MatasanoError::Other("mismatched sizes: {} vs {}"))
    }
}
