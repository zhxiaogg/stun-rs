/**
*
  To allow future revisions of this specification to add new attributes
  if needed, the attribute space is divided into two ranges.
  Attributes with type values between 0x0000 and 0x7FFF are
  comprehension-required attributes, which means that the STUN agent
  cannot successfully process the message unless it understands the
  attribute.  Attributes with type values between 0x8000 and 0xFFFF are
  comprehension-optional attributes, which means that those attributes
  can be ignored by the STUN agent if it does not understand them.
*/
#[derive(Eq, PartialEq, Debug)]
pub enum Attribute {
    MappedAddress(Address),
    // same as MappedAddress, but bits are xored with the magic cookie
    XorMappedAddress(Address),
    // user credentials
    UserName(String),
    // hmac-sha1 of the message
    MessageIntegrity([u8; 20]),
    // crc-32 of the message
    FingerPrint(u32),
    ErrorCode { code: u32, reason: String },
    Realm(String),
    Nonce(String),
    // a list of unknown attribute kinds
    UnknownAttributes(Vec<u16>),
    Software(String),
    AlternateServer(Address),
    // unrecognized attributes
    UnRecognized { kind: u16 },
}

#[derive(Debug, Eq, PartialEq)]
pub struct Address {
    pub address: Vec<u8>,
    pub port: u16,
    pub ip_kind: IPKind,
}

impl Address {
    pub fn ipv4(address: [u8; 4], port: u16) -> Address {
        Address {
            address: address.to_vec(),
            port,
            ip_kind: IPKind::IPv4,
        }
    }

    pub fn ipv6(address: [u8; 16], port: u16) -> Address {
        Address {
            address: address.to_vec(),
            port,
            ip_kind: IPKind::IPv6,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum IPKind {
    IPv4,
    IPv6,
}
