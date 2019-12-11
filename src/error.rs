use std::error;
use std::fmt;
use std::io;

use bulletproofs::r1cs::R1CSError;
use serde::de::Error as SerdeDeError;
use serde::ser::Error as SerdeSerError;

macro_rules! from_error {
    ($t:ty, $id:ident) => {
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Error::$id(e)
            }
        }
    };
}

/// Standard error for the interface
#[derive(Debug)]
pub enum Error {
    /// [`R1CSError`]
    R1CS(R1CSError),
    /// I/O [`io::Error`]
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::R1CS(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::R1CS(_) => None, // R1CSError doesnt implement std error
        }
    }
}

impl SerdeDeError for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        Error::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("Serde error: {}", msg),
        ))
    }
}

impl SerdeSerError for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        Error::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("Serde error: {}", msg),
        ))
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Error::Io(e) => e,
            Error::R1CS(e) => io::Error::new(io::ErrorKind::Other, e.to_string()),
        }
    }
}

from_error!(io::Error, Io);
from_error!(R1CSError, R1CS);
