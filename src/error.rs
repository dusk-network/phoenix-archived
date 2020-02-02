use crate::{Idx, Note, Nullifier};

use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt;
use std::io;
use std::sync::{MutexGuard, TryLockError};

use bulletproofs::r1cs::R1CSError;

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
    /// [`R1CSError`]
    R1CS(R1CSError),
    /// I/O [`io::Error`]
    Io(io::Error),
    /// Field operation error
    Field(String),
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
    pub fn generic<T>(_e: T) -> Error {
        Error::Generic
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::R1CS(e) => write!(f, "{}", e),
            Error::Field(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
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

impl Into<tonic::Status> for Error {
    fn into(self) -> tonic::Status {
        // TODO - Improve the error mapping to tonic codes
        tonic::Status::new(tonic::Code::Internal, format!("{}", self))
    }
}

from_error!(io::Error, Io);
from_error!(R1CSError, R1CS);
from_error_unit!(
    TryLockError<MutexGuard<'_, HashMap<Idx, Box<(dyn Note + 'static)>>>>,
    NotReady
);
from_error_unit!(TryLockError<MutexGuard<'_, HashSet<Nullifier>>>, NotReady);
