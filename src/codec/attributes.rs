use crate::messages::Attribute;
use bytes::Buf;

pub fn decode_attribute(buf: &mut dyn Buf) -> Attribute {
    let attribute_type = buf.get_u16();
    let attribute_value_size = buf.get_u16();
    let mut bytes = Vec::with_capacity(attribute_value_size as usize);
    buf.copy_to_slice(bytes.as_mut());
    match attribute_type {
        // Comprehension-required range (0x0000-0x7FFF):
        // Reserved
        0x0000 => Attribute::UnRecognized { kind: 0x0000 },
        // MAPPED-ADDRESS
        0x0001 => Attribute::UnRecognized { kind: 0x0000 },
        // (Reserved; was RESPONSE-ADDRESS)
        0x0002 => Attribute::UnRecognized { kind: 0x0000 },
        // (Reserved; was CHANGE-ADDRESS)
        0x0003 => Attribute::UnRecognized { kind: 0x0000 },
        //(Reserved; was SOURCE-ADDRESS)
        0x0004 => Attribute::UnRecognized { kind: 0x0000 },
        // (Reserved; was CHANGED-ADDRESS)
        0x0005 => Attribute::UnRecognized { kind: 0x0000 },
        // USERNAME
        0x0006 => Attribute::UnRecognized { kind: 0x0000 },
        // (Reserved; was PASSWORD)
        0x0007 => Attribute::UnRecognized { kind: 0x0000 },
        // MESSAGE-INTEGRITY
        0x0008 => Attribute::UnRecognized { kind: 0x0000 },
        // ERROR-CODE
        0x0009 => Attribute::UnRecognized { kind: 0x0000 },
        // UNKNOWN-ATTRIBUTES
        0x000A => Attribute::UnRecognized { kind: 0x0000 },
        // (Reserved; was REFLECTED-FROM)
        0x000B => Attribute::UnRecognized { kind: 0x0000 },
        // REALM
        0x0014 => Attribute::UnRecognized { kind: 0x0000 },
        // NONCE
        0x0015 => Attribute::UnRecognized { kind: 0x0000 },
        // XOR-MAPPED-ADDRESS
        0x0020 => Attribute::UnRecognized { kind: 0x0000 },

        // Comprehension-optional range (0x8000-0xFFFF)
        0x8022 => Attribute::Software(String::from_utf8(bytes).unwrap()),
        //ALTERNATE-SERVER
        0x8023 => Attribute::UnRecognized { kind: 0x0000 },
        //FINGERPRINT
        0x8028 => Attribute::UnRecognized { kind: 0x0000 },
        kind => Attribute::UnRecognized { kind: kind },
    }
}
