// defines the 4 kinds of message classes
mod message_class;

pub use message_class::MessageClass;

mod message_method;

pub use message_method::MessageMethod;

mod transaction_id;

pub use transaction_id::TransactionID;

mod attributes;

pub use attributes::*;

#[derive(Debug, Eq, PartialEq)]
pub struct Message {
    // 2 bit
    pub message_class: MessageClass,
    // 12 bit
    pub message_method: MessageMethod,
    // 18 bit
    // pub message_length: u32,
    // 96 bit
    pub transaction_id: TransactionID,
    // body: 0 or more attributes, padded to 4 bytes for each attribute
    pub attributes: Vec<Attribute>,
}
