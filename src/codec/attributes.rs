use bytes::{Buf, BufMut};

use crate::codec::error::CodecError;
use crate::codec::MAGIC_COOKIE;
use crate::messages::{Address, Attribute, IPKind};

use super::Result;

pub fn decode_attribute(buf: &mut dyn Buf, transaction_id: &[u8; 12]) -> Result<Attribute> {
    let attribute_type = buf.get_u16();
    let attribute_value_size = buf.get_u16() as usize;

    match attribute_type {
        // Comprehension-required range (0x0000-0x7FFF):
        // Reserved
        0x0000 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized { kind: 0x0000 })
        }
        // MAPPED-ADDRESS
        0x0001 => decode_mapped_address(buf, attribute_value_size),
        // (Reserved; was RESPONSE-ADDRESS)
        0x0002 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // (Reserved; was CHANGE-ADDRESS)
        0x0003 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        //(Reserved; was SOURCE-ADDRESS)
        0x0004 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // (Reserved; was CHANGED-ADDRESS)
        0x0005 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // USERNAME
        0x0006 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // (Reserved; was PASSWORD)
        0x0007 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // MESSAGE-INTEGRITY
        0x0008 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // ERROR-CODE
        0x0009 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // UNKNOWN-ATTRIBUTES
        0x000A => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // (Reserved; was REFLECTED-FROM)
        0x000B => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // REALM
        0x0014 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // NONCE
        0x0015 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        // XOR-MAPPED-ADDRESS
        0x0020 => decode_xor_mapped_address(buf, attribute_value_size, transaction_id),

        // Comprehension-optional range (0x8000-0xFFFF)
        0x8022 => {
            let mut bytes = vec![0u8; attribute_value_size];
            buf.copy_to_slice(bytes.as_mut());
            Ok(Attribute::Software(String::from_utf8(bytes)?))
        }
        //ALTERNATE-SERVER
        0x8023 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        //FINGERPRINT
        0x8028 => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
        _ => {
            buf.advance(attribute_value_size);
            Ok(Attribute::UnRecognized {
                kind: attribute_type,
            })
        }
    }
}

pub fn encode_attribute(
    attribute: &Attribute,
    buf: &mut dyn BufMut,
    transaction_id: &[u8; 12],
) -> usize {
    match attribute {
        Attribute::XorMappedAddress(address) => {
            buf.put_u16(0x0020);
            let value_size = if address.ip_kind == IPKind::IPv4 {
                8
            } else {
                20
            };
            buf.put_u16(value_size);
            encode_xor_mapped_address(attribute, buf, transaction_id);
            4 + value_size as usize
        }
        Attribute::Software(software) => {
            let bytes = software.as_bytes();
            buf.put_u16(0x8022);
            buf.put_u16(bytes.len() as u16);
            buf.put_slice(bytes);
            let padding = 4 - bytes.len() % 4;
            if padding != 4 {
                for _ in 0..padding {
                    buf.put_u8(0x00)
                }
            }
            4 + bytes.len() + padding
        }
        Attribute::MappedAddress(address) => {
            buf.put_u16(0x0001);
            let value_size = if address.ip_kind == IPKind::IPv4 {
                8
            } else {
                20
            };
            buf.put_u16(value_size);
            encode_mapped_address(attribute, buf);
            4 + value_size as usize
        }
        _ => panic!("encoding not supported!"),
    }
}

fn decode_mapped_address(buf: &mut dyn Buf, size: usize) -> Result<Attribute> {
    if buf.remaining() < size {
        return Err(CodecError::insufficient_bytes(size, buf.remaining()));
    }
    if buf.get_u8() != 0x00 {
        return Err(CodecError::unexpected("Invalid MappedAddress Codec!"));
    }
    // TODO: validate size
    match buf.get_u8() {
        0x01 => {
            let port = buf.get_u16();
            let mut address = vec![0; 4];
            buf.copy_to_slice(address.as_mut());
            Ok(Attribute::MappedAddress(Address {
                address,
                port,
                ip_kind: IPKind::IPv4,
            }))
        }
        0x02 => {
            let port = buf.get_u16();
            let mut address = vec![0; 16];
            buf.copy_to_slice(address.as_mut());
            Ok(Attribute::MappedAddress(Address {
                address,
                port,
                ip_kind: IPKind::IPv6,
            }))
        }
        v => Err(CodecError::unexpected(&format!("Invalid ip type {}", v))),
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

fn decode_xor_mapped_address(
    buf: &mut dyn Buf,
    size: usize,
    transaction_id: &[u8; 12],
) -> Result<Attribute> {
    if buf.remaining() < size {
        return Err(CodecError::insufficient_bytes(size, buf.remaining()));
    }
    if buf.get_u8() != 0x00 {
        return Err(CodecError::unexpected("Invalid XorMappedAddress Codec!"));
    }
    // TODO: validate size
    match buf.get_u8() {
        0x01 => {
            let port = buf.get_u16() ^ ((MAGIC_COOKIE >> 16) as u16);
            let mut address = vec![0; 4];
            for i in 0..4 {
                address[i] = buf.get_u8() ^ ((MAGIC_COOKIE >> ((4 - i as u32 - 1) * 8)) as u8);
            }
            Ok(Attribute::XorMappedAddress(Address {
                address,
                port,
                ip_kind: IPKind::IPv4,
            }))
        }
        0x02 => {
            let port = buf.get_u16() ^ ((MAGIC_COOKIE >> 16) as u16);
            let mut address = vec![0; 16];
            for i in 0..4 {
                address[i] = buf.get_u8() ^ ((MAGIC_COOKIE >> ((4 - i as u32 - 1) * 8)) as u8);
            }
            for i in 0..12 {
                address[i + 4] = buf.get_u8() ^ (transaction_id[i]);
            }
            Ok(Attribute::XorMappedAddress(Address {
                address,
                port,
                ip_kind: IPKind::IPv6,
            }))
        }
        v => Err(CodecError::unexpected(&format!("Invalid ip type {}", v))),
    }
}

fn encode_xor_mapped_address(
    attribute: &Attribute,
    buf: &mut dyn BufMut,
    transaction_id: &[u8; 12],
) -> usize {
    match attribute {
        Attribute::XorMappedAddress(Address {
            address,
            port,
            ip_kind,
        }) if ip_kind == &IPKind::IPv4 => {
            buf.put_u8(0);
            buf.put_u8(0x01);
            buf.put_u16((*port) ^ ((MAGIC_COOKIE >> 16) as u16));
            for i in 0..4 {
                buf.put_u8(address[i] ^ ((MAGIC_COOKIE >> ((4 - i as u32 - 1) * 8)) as u8));
            }
            8
        }
        Attribute::XorMappedAddress(Address {
            address,
            port,
            ip_kind,
        }) if ip_kind == &IPKind::IPv6 => {
            buf.put_u8(0);
            buf.put_u8(0x02);
            buf.put_u16((*port) ^ ((MAGIC_COOKIE >> 16) as u16));
            for i in 0..4 {
                buf.put_u8(address[i] ^ ((MAGIC_COOKIE >> ((4 - i as u32 - 1) * 8)) as u8));
            }
            for i in 0..12 {
                buf.put_u8(address[i + 4] ^ (transaction_id[i]));
            }
            20
        }
        v => panic!(format!("Should never be here!, {:#?}", v)),
    }
}

mod test {
    use bytes::{Buf, BytesMut};

    use crate::codec::attributes::{decode_attribute, encode_attribute};
    use crate::messages::Attribute;

    #[test]
    pub fn test_encode_decode_ipv4_mapped_address() {
        use super::*;
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
        let decoded_attribute = decode_mapped_address(&mut bytes, 8).unwrap();
        assert_eq!(decoded_attribute, attribute)
    }

    #[test]
    pub fn test_encode_decode_ipv6_mapped_address() {
        use super::*;
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
        let decoded_attribute = decode_mapped_address(&mut bytes, 8).unwrap();
        assert_eq!(decoded_attribute, attribute)
    }

    #[test]
    pub fn test_encode_decode_ipv4_xor_mapped_address() {
        use super::*;
        let address = Address {
            address: vec![0x01, 0x02, 0x03, 0x04],
            port: 0x0101,
            ip_kind: IPKind::IPv4,
        };
        let attribute = Attribute::XorMappedAddress(address);
        let mut buf_mut = BytesMut::with_capacity(1024);
        let transaction_id: [u8; 12] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ];

        let size = encode_xor_mapped_address(&attribute, &mut buf_mut, &transaction_id);
        assert_eq!(size, 8);
        let mut bytes = buf_mut.freeze();
        let decoded_attribute = decode_xor_mapped_address(&mut bytes, 8, &transaction_id).unwrap();
        assert_eq!(decoded_attribute, attribute)
    }

    #[test]
    pub fn test_encode_decode_ipv6_xor_mapped_address() {
        use super::*;
        let ipv6_address = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        let address = Address {
            address: ipv6_address,
            port: 0x0101,
            ip_kind: IPKind::IPv6,
        };
        let attribute = Attribute::XorMappedAddress(address);
        let mut buf_mut = BytesMut::with_capacity(1024);
        let transaction_id: [u8; 12] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ];
        let size = encode_xor_mapped_address(&attribute, &mut buf_mut, &transaction_id);
        assert_eq!(size, 20);
        let mut bytes = buf_mut.freeze();
        let decoded_attribute = decode_xor_mapped_address(&mut bytes, 8, &transaction_id).unwrap();
        assert_eq!(decoded_attribute, attribute)
    }

    #[test]
    pub fn test_encode_decode_software() {
        let attribute = Attribute::Software("test:0.1.0".to_owned());
        let transaction_id = [0u8; 12];
        let mut bytes_mut = BytesMut::new();
        let size = encode_attribute(&attribute, &mut bytes_mut, &transaction_id);
        assert_eq!(16, size);
        let mut buf = bytes_mut.bytes();
        let decode_attribute = decode_attribute(&mut buf, &transaction_id).unwrap();
        assert_eq!(attribute, decode_attribute);
    }
}
