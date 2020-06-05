use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum CodecError {
    InsufficientBytes {
        when: String,
        required: usize,
        actual: usize,
    },
    UnExpected(String),
}

impl Display for CodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::InsufficientBytes {
                when,
                required,
                actual,
            } => write!(
                f,
                "insufficient bytes when {}, required {}, actual: {}",
                when, required, actual
            ),
            CodecError::UnExpected(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for CodecError {
    // need #![feature(backtrace)] declared at the root crate
    // fn backtrace(&self) -> Option<&Backtrace> {
    //     Some(&Backtrace::capture())
    // }
}

impl CodecError {
    pub fn insufficient_bytes(when: &str, required: usize, actual: usize) -> CodecError {
        CodecError::InsufficientBytes {
            when: when.to_owned(),
            required,
            actual,
        }
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
