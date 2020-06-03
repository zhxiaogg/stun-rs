use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum CodecError {
    InsufficientBytes { required: usize, actual: usize },
    UnExpected(String),
}

impl Display for CodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::InsufficientBytes { required, actual } => write!(
                f,
                "insufficient bytes, required {}, actual: {}",
                required, actual
            ),
            CodecError::UnExpected(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for CodecError {}

impl CodecError {
    pub fn insufficient_bytes(required: usize, actual: usize) -> CodecError {
        CodecError::InsufficientBytes { required, actual }
    }

    pub fn unexpected(msg: &str) -> CodecError {
        CodecError::UnExpected(msg.to_owned())
    }
}

impl From<FromUtf8Error> for CodecError {
    fn from(e: FromUtf8Error) -> Self {
        CodecError::unexpected(format!("cannot convert bytes to utf8: {}", e).as_ref())
    }
}
