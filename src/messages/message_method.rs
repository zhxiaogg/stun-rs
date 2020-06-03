#[derive(PartialEq, Eq, Debug)]
pub enum MessageMethod {
    Binding,
    Custom(u16),
}

impl MessageMethod {
    pub fn from(value: u16) -> MessageMethod {
        // make sure the value is at most 12 bits length
        if value & 0xFFF != value {
            panic!(format!("invalid method value: {}", value))
        }
        match value {
            1 => MessageMethod::Binding,
            v => MessageMethod::Custom(v),
        }
    }
    pub fn value(&self) -> u16 {
        match self {
            MessageMethod::Binding => 0x0001,
            MessageMethod::Custom(v) => *v,
        }
    }
}

mod test {
    #[test]
    fn can_deserialize_binding_method() {
        use super::*;
        assert_eq!(MessageMethod::from(1), MessageMethod::Binding);
    }
}
