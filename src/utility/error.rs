use crypto::symmetriccipher;

use serialize::{base64, hex};

use std::fmt::{Display, Formatter, Result};
use std::error::Error;
use std::{io, str, string};

#[derive(Debug)]
pub enum MatasanoError {
    Crypto(symmetriccipher::SymmetricCipherError),
    Io(io::Error),
    Base64(base64::FromBase64Error),
    Hex(hex::FromHexError),
    Utf8(string::FromUtf8Error),
    Other(&'static str),
}

impl Display for MatasanoError {
    fn fmt(&self, formatter: &mut Formatter) -> Result {
        match *self {
            MatasanoError::Crypto(_) => write!(formatter, "Crypto error: {}", self.description()),
            MatasanoError::Io(ref err) => write!(formatter, "IO Error: {}", err),
            MatasanoError::Base64(ref err) => write!(formatter, "Base64 error: {}", err),
            MatasanoError::Hex(ref err) => write!(formatter, "HexError error: {}", err),
            MatasanoError::Utf8(ref err) => write!(formatter, "Utf8Error error: {}", err),
            MatasanoError::Other(ref err) => write!(formatter, "Other error: {}", err),
        }
    }
}

impl Error for MatasanoError {
    fn description(&self) -> &str {
        match *self {
            MatasanoError::Crypto(ref err) => {
                match *err {
                    symmetriccipher::SymmetricCipherError::InvalidLength => "Invalid length",
                    symmetriccipher::SymmetricCipherError::InvalidPadding => "Invalid padding",
                }
            }
            MatasanoError::Io(ref err) => err.description(),
            MatasanoError::Base64(ref err) => err.description(),
            MatasanoError::Hex(ref err) => err.description(),
            MatasanoError::Utf8(ref err) => err.description(),
            MatasanoError::Other(ref err) => err,
        }
    }
}

impl From<io::Error> for MatasanoError {
    fn from(err: io::Error) -> MatasanoError {
        MatasanoError::Io(err)
    }
}

impl From<base64::FromBase64Error> for MatasanoError {
    fn from(err: base64::FromBase64Error) -> MatasanoError {
        MatasanoError::Base64(err)
    }
}

impl From<hex::FromHexError> for MatasanoError {
    fn from(err: hex::FromHexError) -> MatasanoError {
        MatasanoError::Hex(err)
    }
}

impl From<string::FromUtf8Error> for MatasanoError {
    fn from(err: string::FromUtf8Error) -> MatasanoError {
        MatasanoError::Utf8(err)
    }
}

impl From<symmetriccipher::SymmetricCipherError> for MatasanoError {
    fn from(err: symmetriccipher::SymmetricCipherError) -> MatasanoError {
        MatasanoError::Crypto(err)
    }
}
