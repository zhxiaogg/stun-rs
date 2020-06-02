use bytes::{Buf, BufMut};

use crate::messages::{Address, Attribute, IPKind};

pub fn decode_attribute(buf: &mut dyn Buf) -> Attribute {
    let attribute_type = buf.get_u16();
    let attribute_value_size = buf.get_u16() as usize;

    match attribute_type {
        // Comprehension-required range (0x0000-0x7FFF):
        // Reserved
        0x0000 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // MAPPED-ADDRESS
        0x0001 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // (Reserved; was RESPONSE-ADDRESS)
        0x0002 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // (Reserved; was CHANGE-ADDRESS)
        0x0003 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        //(Reserved; was SOURCE-ADDRESS)
        0x0004 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // (Reserved; was CHANGED-ADDRESS)
        0x0005 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // USERNAME
        0x0006 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // (Reserved; was PASSWORD)
        0x0007 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // MESSAGE-INTEGRITY
        0x0008 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // ERROR-CODE
        0x0009 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // UNKNOWN-ATTRIBUTES
        0x000A => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // (Reserved; was REFLECTED-FROM)
        0x000B => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // REALM
        0x0014 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // NONCE
        0x0015 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        // XOR-MAPPED-ADDRESS
        0x0020 => Attribute::UnRecognized { kind: 0x0000 },

        // Comprehension-optional range (0x8000-0xFFFF)
        0x8022 => {
            let mut bytes = Vec::with_capacity(attribute_value_size as usize);
            buf.copy_to_slice(bytes.as_mut());
            Attribute::Software(String::from_utf8(bytes).unwrap())
        }
        //ALTERNATE-SERVER
        0x8023 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        //FINGERPRINT
        0x8028 => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: 0x0000 }
        }
        kind => {
            buf.advance(attribute_value_size);
            Attribute::UnRecognized { kind: kind }
        }
    }
}

fn decode_mapped_address(buf: &mut dyn Buf, size: usize) -> Attribute {
    if buf.get_u8() != 0x00 {
        panic!("Invalid MappedAddress Codec!");
    }
    // TODO: validate size
    match buf.get_u8() {
        0x01 => {
            let port = buf.get_u16();
            let mut address = vec![0; 4];
            buf.copy_to_slice(address.as_mut());
            Attribute::MappedAddress(Address {
                address,
                port,
                ip_kind: IPKind::IPv4,
            })
        }
        0x02 => {
            let port = buf.get_u16();
            let mut address = vec![0; 16];
            buf.copy_to_slice(address.as_mut());
            Attribute::MappedAddress(Address {
                address,
                port,
                ip_kind: IPKind::IPv6,
            })
        }
        v => panic!(format!("Invalid ip type {}", v)),
    }
}

fn encode_mapped_address(v: &Attribute, buf: &mut dyn BufMut) -> usize {
    match v {
        Attribute::MappedAddress(Address {
            address,
            port,
            ip_kind,
        }) if ip_kind == &IPKind::IPv4 => {
            buf.put_u8(0);
            buf.put_u8(0x01);
            buf.put_u16(*port);
            for i in 0..4 {
                buf.put_u8(address[i]);
            }
            8
        }
        Attribute::MappedAddress(Address {
            address,
            port,
            ip_kind,
        }) if ip_kind == &IPKind::IPv6 => {
            buf.put_u8(0);
            buf.put_u8(0x02);
            buf.put_u16(*port);
            for i in 0..16 {
                buf.put_u8(address[i]);
            }
            20
        }
        _ => panic!("Should never be here!".to_owned()),
    }
}

// fn decode_xor_mapped_address(buf: &mut dyn Buf, size: usize) -> Attribute {}
//
// fn encode_xor_mapped_address(v: Attribute, buf: &mut dyn BufMut) -> usize {
//     match v {
//         Attribute::XorMappedAddress(address) => {}
//         _ => panic!("".to_owned())
//     }
// }

mod test {
    use bytes::{BufMut, BytesMut};

    #[test]
    pub fn test_encode_decode_ipv4_mapped_address() {
        use super::*;
        use crate::messages::*;
        let address = Address {
            address: vec![0x01, 0x02, 0x03, 0x04],
            port: 0x0101,
            ip_kind: IPKind::IPv4,
        };
        let attribute = Attribute::MappedAddress(address);
        let mut buf_mut = BytesMut::with_capacity(1024);
        let size = encode_mapped_address(&attribute, &mut buf_mut);
        assert_eq!(size, 8);
        let mut bytes = buf_mut.freeze();
        let decoded_attribute = decode_mapped_address(&mut bytes, 8);
        assert_eq!(decoded_attribute, attribute)
    }

    #[test]
    pub fn test_encode_decode_ipv6_mapped_address() {
        use super::*;
        use crate::messages::*;
        let ipv6_address = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        let address = Address {
            address: ipv6_address,
            port: 0x0101,
            ip_kind: IPKind::IPv6,
        };
        let attribute = Attribute::MappedAddress(address);
        let mut buf_mut = BytesMut::with_capacity(1024);
        let size = encode_mapped_address(&attribute, &mut buf_mut);
        assert_eq!(size, 20);
        let mut bytes = buf_mut.freeze();
        let decoded_attribute = decode_mapped_address(&mut bytes, 8);
        assert_eq!(decoded_attribute, attribute)
    }
}
