use std::fs::File;
use std::io::{BufRead, BufReader, Error, Lines, Read};

pub fn lines_iterator(path: &str) -> Result<Lines<BufReader<File>>, Error> {
    Ok(BufReader::new(File::open(path)?).lines())
}

pub fn dump_bytes(path: &str) -> Result<Vec<u8>, Error> {
    let mut raw_contents = Vec::new();
    let _ = File::open(path)?.read_to_end(&mut raw_contents)?;
    Ok(raw_contents)
}
