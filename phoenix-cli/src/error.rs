use std::error;
use std::fmt;
use std::io;

use phoenix_lib::Error as PhoenixError;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use tonic::transport::Error as TonicTransportError;
use tonic::Status as TonicStatus;

macro_rules! from_error {
    ($t:ty, $id:ident) => {
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Error::$id(e)
            }
        }
    };
}

macro_rules! from_error_unit {
    ($t:ty, $id:ident) => {
        impl From<$t> for Error {
            fn from(_e: $t) -> Self {
                Error::$id
            }
        }
    };
}

/// Standard error for the interface
#[derive(Debug)]
pub enum Error {
    /// [`PhoenixError`]
    Phoenix(PhoenixError),
    /// I/O [`io::Error`]
    Io(io::Error),
    /// [`TonicTransportError`]
    TonicTransport(TonicTransportError),
    /// [`TonicStatus`]
    TonicStatus(TonicStatus),
    /// Unexpected response from the phoenix server
    UnexpectedResponse(String),
    /// [`PoisonError`]
    MutexPoison,
    /// Invalid input provided
    InvalidInput,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Phoenix(e) => write!(f, "{}", e),
            Error::Io(e) => write!(f, "{}", e),
            Error::TonicTransport(e) => write!(f, "{}", e),
            Error::TonicStatus(e) => write!(f, "{}", e),
            Error::UnexpectedResponse(e) => write!(f, "{}", e),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Phoenix(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::TonicTransport(e) => Some(e),
            Error::TonicStatus(e) => Some(e),
            _ => None,
        }
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Error::Phoenix(e) => e.into(),
            Error::Io(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", self)),
        }
    }
}

from_error!(PhoenixError, Phoenix);
from_error!(io::Error, Io);
from_error!(TonicTransportError, TonicTransport);
from_error!(TonicStatus, TonicStatus);
from_error_unit!(PoisonError<MutexGuard<'_, String>>, MutexPoison);
