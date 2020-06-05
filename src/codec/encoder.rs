use bytes::{Buf, BufMut, BytesMut};

use crate::codec::attributes::encode_attribute;
use crate::codec::MAGIC_COOKIE;
use crate::messages::*;

pub struct Encoder {}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {}
    }

    pub fn encode(&self, message: &Message, buf: &mut dyn BufMut) -> usize {
        let mut size = 0usize;

        let mut header = 0x0000u16;
        // encode message class
        header = header | (((message.message_class.value() as u16) & 0b10) << 7);
        header = header | (((message.message_class.value() as u16) & 0b01) << 4);

        // encode message method
        let message_method_code = message.message_method.value() & 0xFFF;
        header = header
            | (message_method_code & 0x000F)
            | ((message_method_code & 0x0070) << 1)
            | ((message_method_code & 0x0F80) << 2);

        buf.put_u16(header);
        size += 2;

        // encode body length
        let mut body_bytes = BytesMut::with_capacity(256);
        let mut body_size: usize = 0usize;
        let transaction_id: &[u8; 12] = &message.transaction_id.value;
        for attribute in &message.attributes {
            body_size += encode_attribute(attribute, &mut body_bytes, transaction_id);
        }

        // header, message body length
        buf.put_u16(body_size as u16);
        size += 2;
        // header, magic cookie
        buf.put_u32(MAGIC_COOKIE);
        size += 4;
        // header, transaction id
        buf.put_slice(transaction_id);
        size += 12;

        // body bytes
        buf.put_slice(body_bytes.bytes());
        size += body_size;

        size
    }
}
