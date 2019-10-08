use ethabi;
use failure::Fail;
use std::io;
use std::string::ToString;

/// Contract Service Errors
#[derive(Debug, Clone, Fail)]
pub enum Error {
    /// IO Error
    #[fail(display = "IO error: {}", _0)]
    IO(String),

    /// Invalid Contract
    #[fail(display = "Invalid contract: {}", _0)]
    InvalidContract(String),
}

impl From<ethabi::Error> for Error {
    fn from(_: ethabi::Error) -> Self {
        Error::InvalidContract("ethabi error".to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err.to_string())
    }
}
