use crypto::symmetriccipher::SymmetricCipherError;

use serialize::hex;

use std::fmt::{Display, Formatter, Result};
use std::error::Error;
use std::io;

#[derive(Debug)]
pub enum MatasanoError {
    Crypto(SymmetricCipherError),
    Io(io::Error),
    FromHex(hex::FromHexError),
    Other(&'static str),
}

impl Display for MatasanoError {
    fn fmt(&self, formatter: &mut Formatter) -> Result {
        match *self {
            MatasanoError::Crypto(_) => write!(formatter, "Crypto error: {}", self.description()),
            MatasanoError::Io(ref err) => write!(formatter, "IO error: {}", err),
            MatasanoError::FromHex(ref err) => write!(formatter, "FromHex error: {}", err),
            MatasanoError::Other(ref err) => write!(formatter, "Other error: {}", err),
        }
    }
}

impl Error for MatasanoError {
    fn description(&self) -> &str {
        match *self {
            MatasanoError::Crypto(ref err) => match *err {
                SymmetricCipherError::InvalidLength => "Invalid length",
                SymmetricCipherError::InvalidPadding => "Invalid padding",
            },
            MatasanoError::Io(ref err) => err.description(),
            MatasanoError::FromHex(ref err) => err.description(),
            MatasanoError::Other(ref err) => err,
        }
    }
}

impl From<io::Error> for MatasanoError {
    fn from(err: io::Error) -> MatasanoError {
        MatasanoError::Io(err)
    }
}

impl From<hex::FromHexError> for MatasanoError {
    fn from(err: hex::FromHexError) -> MatasanoError {
        MatasanoError::FromHex(err)
    }
}

impl From<SymmetricCipherError> for MatasanoError {
    fn from(err: SymmetricCipherError) -> MatasanoError {
        MatasanoError::Crypto(err)
    }
}
