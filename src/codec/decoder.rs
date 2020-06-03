use bytes::Buf;

use crate::codec::error::CodecError;
use crate::codec::MAGIC_COOKIE;
use crate::messages::*;

use super::attributes::decode_attribute;
use super::Result;

pub struct Decoder {}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder {}
    }

    pub fn decode(&self, buf: &mut dyn Buf) -> Result<Message> {
        // verify & decode headers
        if buf.remaining() < 20 {
            return Err(CodecError::insufficient_bytes(20, buf.remaining()));
        }
        let header = buf.get_u16();
        if header & 0xC000 != 0x0000 {
            return Err(CodecError::unexpected("invalid flag bits."));
        }
        let message_length = buf.get_u16() as usize;
        if message_length & 0x0003 != 0 {
            return Err(CodecError::unexpected(&format!(
                "invalid message length: {}",
                message_length
            )));
        }
        let magic_cookie = buf.get_u32();
        if magic_cookie != MAGIC_COOKIE {
            return Err(CodecError::unexpected(&format!(
                "invalid matic cookie: {}",
                magic_cookie
            )));
        }

        let message_class_code = ((header & 0x0100) >> 7) | ((header & 0x0010) >> 4);
        let message_class = MessageClass::from(message_class_code as u8);
        let message_method_code =
            ((header & 0x3E00) >> 2) | ((header & 0x00E0) >> 1) | (header & 0x000F);
        let message_method = MessageMethod::from(message_method_code);
        let mut transaction_id_bytes: [u8; 12] = [0; 12];
        for i in 0..12 {
            transaction_id_bytes[i] = buf.get_u8();
        }
        let transaction_id = TransactionID::from(transaction_id_bytes);

        // verify and decode body
        if buf.remaining() != message_length {
            return Err(CodecError::insufficient_bytes(
                message_length,
                buf.remaining(),
            ));
        }
        let mut attributes: Vec<Attribute> = Vec::new();
        while buf.has_remaining() {
            let attribute = decode_attribute(buf, &transaction_id_bytes)?;
            attributes.push(attribute);
        }

        // decode
        let msg = Message {
            message_class: message_class,
            message_method: message_method,
            transaction_id: transaction_id,
            attributes: attributes,
        };
        Result::Ok(msg)
    }
}
