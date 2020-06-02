mod attributes;

mod decoder;
pub use decoder::*;

// magic cookie for STUN message is a constant
pub const MAGIC_COOKIE: u32 = 0x2112A442;
