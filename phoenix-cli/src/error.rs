use std::error;
use std::fmt;
use std::io;

use phoenix_lib::Error as PhoenixError;

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
    /// [`Phoenix Error`]
    Phoenix(PhoenixError),
    /// I/O [`io::Error`]
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Phoenix(e) => write!(f, "{}", e),
            Error::Io(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Phoenix(e) => Some(e),
            Error::Io(e) => Some(e),
        }
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Error::Phoenix(e) => e.into(),
            Error::Io(e) => e,
        }
    }
}

from_error!(PhoenixError, Phoenix);
from_error!(io::Error, Io);
