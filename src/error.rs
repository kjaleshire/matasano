use crypto::symmetriccipher;

use serialize::hex;

use std::fmt::{Display, Formatter, Result};
use std::error::Error;
use std::{io, str, string};

#[derive(Debug)]
pub enum MatasanoError {
    Crypto(symmetriccipher::SymmetricCipherError),
    Io(io::Error),
    FromHex(hex::FromHexError),
    FromUtf8(string::FromUtf8Error),
    Other(&'static str),
    StrUtf8(str::Utf8Error),
}

impl Display for MatasanoError {
    fn fmt(&self, formatter: &mut Formatter) -> Result {
        match *self {
            MatasanoError::Crypto(_) => write!(formatter, "Crypto error: {}", self.description()),
            MatasanoError::Io(ref err) => write!(formatter, "IO Error: {}", err),
            MatasanoError::FromHex(ref err) => write!(formatter, "FromHexError error: {}", err),
            MatasanoError::FromUtf8(ref err) => write!(formatter, "FromUtf8Error error: {}", err),
            MatasanoError::Other(ref err) => write!(formatter, "Other error: {}", err),
            MatasanoError::StrUtf8(ref err) => write!(formatter, "str Utf8Error error: {}", err),
        }
    }
}

impl Error for MatasanoError {
    fn description(&self) -> &str {
        match *self {
            MatasanoError::Crypto(ref err) => match *err {
                symmetriccipher::SymmetricCipherError::InvalidLength => "Invalid length",
                symmetriccipher::SymmetricCipherError::InvalidPadding => "Invalid padding",
            },
            MatasanoError::Io(ref err) => err.description(),
            MatasanoError::FromHex(ref err) => err.description(),
            MatasanoError::FromUtf8(ref err) => err.description(),
            MatasanoError::Other(ref err) => err,
            MatasanoError::StrUtf8(ref err) => err.description(),
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

impl From<string::FromUtf8Error> for MatasanoError {
    fn from(err: string::FromUtf8Error) -> MatasanoError {
        MatasanoError::FromUtf8(err)
    }
}

impl From<str::Utf8Error> for MatasanoError {
    fn from(err: str::Utf8Error) -> MatasanoError {
        MatasanoError::StrUtf8(err)
    }
}

impl From<symmetriccipher::SymmetricCipherError> for MatasanoError {
    fn from(err: symmetriccipher::SymmetricCipherError) -> MatasanoError {
        MatasanoError::Crypto(err)
    }
}
