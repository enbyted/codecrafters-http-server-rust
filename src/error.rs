use std::{str::Utf8Error, string::FromUtf8Error};

use thiserror::Error;
use tokio::io;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("I/O Error: {0}")]
    IoError(io::ErrorKind),
    #[error("Failed to decode utf-8 stream")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("Failed to decode utf-8 stream")]
    Utf8Error(#[from] Utf8Error),
    #[error("Unknown HTTP method '{0}'")]
    UnknownMethod(String),
    #[error("Invalid status line '{0}'")]
    InvalidStatusLine(String),
    #[error("Unsupported HTTP version '{0}'")]
    UnsupportedHttpVersion(String),
    #[error("Invalid header line: '{0}")]
    InvalidHeaderLine(String),
    #[error("Unexpected end of urlencoded string: '{0}'")]
    UnexpectedEndOfUrlEncodedString(String),
    #[error("Invalid urlencoded sequence '{0}' in '{1}'")]
    InvalidUrlEncodedSequence(String, String),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::IoError(value.kind())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
