use bytes::{Buf, BufMut};

use crate::codec::MAGIC_COOKIE;
use crate::messages::*;

use super::attributes::decode_attribute;

pub struct Encoder {}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {}
    }

    pub fn encode(&self, message: &Message, buf_mut: &mut dyn BufMut) -> usize {
        0
    }
}
