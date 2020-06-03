#[derive(Eq, PartialEq, Debug)]
pub enum MessageClass {
    Request,
    SuccessResponse,
    FailureResponse,
    Indication,
}

impl MessageClass {
    pub fn from(value: u8) -> MessageClass {
        match value & 0x03 {
            0b00 => MessageClass::Request,
            0b01 => MessageClass::Indication,
            0b10 => MessageClass::SuccessResponse,
            0b11 => MessageClass::FailureResponse,
            _ => panic!("should never be here!"),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            MessageClass::Request => 0b00,
            MessageClass::Indication => 0b01,
            MessageClass::SuccessResponse => 0b10,
            MessageClass::FailureResponse => 0b1,
        }
    }
}

mod test {
    #[test]
    fn can_deserialize_message_class_correctly() {
        use super::*;
        assert_eq!(MessageClass::from(0b00), MessageClass::Request);
        assert_eq!(MessageClass::from(0b01), MessageClass::Indication);
        assert_eq!(MessageClass::from(0b10), MessageClass::SuccessResponse);
        assert_eq!(MessageClass::from(0b11), MessageClass::FailureResponse);
    }
}
