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
}

mod test {
    #[test]
    fn can_deserialize_binding_method() {
        use super::*;
        assert_eq!(MessageMethod::from(1), MessageMethod::Binding);
    }
}
