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
            return Err(CodecError::insufficient_bytes(
                "decode header",
                20,
                buf.remaining(),
            ));
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
        buf.copy_to_slice(&mut transaction_id_bytes);
        let transaction_id = TransactionID::from(transaction_id_bytes);

        // verify and decode body
        if buf.remaining() < message_length {
            return Err(CodecError::insufficient_bytes(
                "decode body",
                message_length,
                buf.remaining(),
            ));
        }
        let mut attributes: Vec<Attribute> = Vec::new();
        let remain = buf.remaining() - message_length;
        while buf.remaining() > remain {
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

mod test {
    use bytes::{Buf, BytesMut};

    use crate::codec::{Decoder, Encoder};
    use crate::messages::*;

    #[test]
    pub fn test_encode_decode_message() {
        let transaction_id_codes = [1u8; 12];
        let message = Message {
            message_class: MessageClass::Request,
            message_method: MessageMethod::Binding,
            transaction_id: TransactionID::from(transaction_id_codes),
            attributes: vec![Attribute::XorMappedAddress(Address::ipv4([1u8; 4], 8080))],
        };
        let mut bytes_mut = BytesMut::with_capacity(0);
        let size = Encoder::new().encode(&message, &mut bytes_mut);
        assert_eq!(size, 20 + 12);

        let mut bytes = bytes_mut.bytes();
        let decoded_message = Decoder::new().decode(&mut bytes).unwrap();
        assert_eq!(decoded_message, message)
    }

    #[test]
    pub fn test_encode_decode_message_with_multiple_attributes() {
        let transaction_id_codes = [1u8; 12];
        let message = Message {
            message_class: MessageClass::Request,
            message_method: MessageMethod::Binding,
            transaction_id: TransactionID::from(transaction_id_codes),
            attributes: vec![
                Attribute::Software("stun-rs/client:0.1.0".to_owned()),
                Attribute::XorMappedAddress(Address::ipv4([1u8; 4], 8080)),
            ],
        };
        let mut bytes_mut = BytesMut::with_capacity(0);
        Encoder::new().encode(&message, &mut bytes_mut);

        let mut bytes = bytes_mut.bytes();
        let decoded_message = Decoder::new().decode(&mut bytes).unwrap();
        assert_eq!(decoded_message, message)
    }
}
