pub use decoder::*;
pub use encoder::*;

use crate::codec::error::CodecError;

mod attributes;

mod decoder;

mod encoder;

pub mod error;

pub type Result<T> = std::result::Result<T, CodecError>;

// magic cookie for STUN message is a constant
pub const MAGIC_COOKIE: u32 = 0x2112A442;
