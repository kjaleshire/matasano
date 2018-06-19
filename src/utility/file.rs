use std::fs::File;
use std::io::{BufReader, Read};

use super::error::{Result, ResultExt};

pub fn buffered_file_reader(path: &str) -> Result<BufReader<File>> {
    let file = File::open(path).chain_err(|| "unable to open file")?;
    Ok(BufReader::new(file))
}

pub fn dump_bytes(path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path).chain_err(|| "unable to open file")?;
    let file_metadata = file
        .metadata()
        .chain_err(|| "unable to fetch file metadata")?;
    let size = file_metadata.len() as usize;

    let mut raw_bytes = Vec::with_capacity(size);
    let read_size = file
        .read_to_end(&mut raw_bytes)
        .chain_err(|| "could not read to end of file")?;

    match read_size == size {
        true => Ok(raw_bytes),
        false => bail!("mismatched sizes: {} vs {}"),
    }
}
