#[derive(PartialEq, Eq, Debug)]
pub struct TransactionID {
    pub value: [u8; 12],
}

impl TransactionID {
    pub fn from(value: [u8; 12]) -> TransactionID {
        TransactionID { value }
    }
}

mod test {
    #[test]
    fn test_transaction_id_equality_check() {
        use super::*;
        let id1 = TransactionID::from([1; 12]);
        let id2 = TransactionID::from([1; 12]);
        assert_eq!(id1, id2)
    }
}
