// defines the 4 kinds of message classes
mod message_class;
pub use message_class::*;

mod message_method;
pub use message_method::*;

mod transaction_id;
pub use transaction_id::*;

// magic cookie for STUN message is a constant
pub const MAGIC_COOKIE: u32 = 0x2112A442;

mod attributes;
pub use attributes::*;

pub struct Message {
    // 2 bit
    pub message_class: MessageClass,
    // 12 bit
    pub message_method: MessageMethod,
    // 18 bit
    pub message_length: u32,
    // 96 bit
    pub transaction_id: TransactionID,
    // body: 0 or more attributes, padded to 4 bytes for each attribute
    pub attributes: Vec<Attribute>,
}
