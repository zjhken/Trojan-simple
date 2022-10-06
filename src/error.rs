use std::error;
use std::fmt::{self, Debug, Formatter};
use std::io;

#[derive(Clone)]
pub struct CustError {
    pub message: String,
}

impl CustError {
    pub fn new<S>(message: S) -> CustError
    where
        S: Into<String>,
    {
        CustError {
            message: message.into(),
        }
    }
}

impl Debug for CustError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Display for CustError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for CustError {}

impl From<io::Error> for CustError {
    fn from(err: io::Error) -> CustError {
        CustError::new(err.to_string())
    }
}

impl From<CustError> for io::Error {
    fn from(err: CustError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err.message)
    }
}
