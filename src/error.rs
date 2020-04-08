use std::error;
use std::fmt;
use std::io;

use algebra::serialize::SerializationError as JubJubSerializationError;

macro_rules! from_error {
    ($t:ty, $id:ident) => {
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Error::$id(e)
            }
        }
    };
}

#[derive(Debug)]
/// Standard error for the interface
pub enum Error {
    /// I/O [`io::Error`]
    Io(io::Error),
    /// Fmt [`fmt::Error`]
    Fmt(fmt::Error),
    /// Field operation error
    Field(String),
    /// Error during JubJub point serialization
    JubJubSerialization(JubJubSerializationError),
    /// Cryptographic bottom
    Generic,
    /// Resource not ready
    NotReady,
    /// The transaction needs to be prepared before it can be stored
    TransactionNotPrepared,
    /// Failed to create the fee output
    FeeOutput,
    /// Invalid compressed point provided
    InvalidPoint,
    /// Invalid parameters provided to the function
    InvalidParameters,
    /// Maximum number of notes per transaction exceeded
    MaximumNotes,
}

impl Error {
    /// Return a generic error from any type. Represents a cryptographic bottom
    pub fn generic<T>(_e: T) -> Error {
        Error::Generic
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Fmt(e) => write!(f, "{}", e),
            Error::JubJubSerialization(e) => write!(f, "{}", e),
            //Error::R1CS(e) => write!(f, "{}", e),
            Error::Field(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Fmt(e) => Some(e),
            Error::JubJubSerialization(e) => Some(e),
            _ => None,
        }
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Error::Io(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", self)),
        }
    }
}

impl Into<fmt::Error> for Error {
    fn into(self) -> fmt::Error {
        fmt::Error {}
    }
}

impl From<Error> for tonic::Status {
    fn from(e: Error) -> Self {
        // TODO - Improve the error mapping to tonic codes
        tonic::Status::new(tonic::Code::Internal, format!("{}", e))
    }
}

from_error!(io::Error, Io);
from_error!(fmt::Error, Fmt);
from_error!(JubJubSerializationError, JubJubSerialization);
