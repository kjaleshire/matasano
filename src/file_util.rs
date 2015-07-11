use std::fs::File;
use std::io::{BufRead, BufReader, Error, Lines, Read};

pub fn lines_iterator(path: &str) -> Lines<BufReader<File>> {
    BufReader::new(File::open(path).unwrap()).lines()
}

pub fn dump_bytes(path: &str) -> Result<Vec<u8>, Error> {
    let mut raw_contents = Vec::new();
    match File::open(path).unwrap().read_to_end(&mut raw_contents) {
        Ok(_) => Ok(raw_contents),
        Err(e) => Err(e)
    }
}
