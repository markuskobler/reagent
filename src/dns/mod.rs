#[allow(unused_imports)]
use std::{io, result};

pub use dns::message::Message;

#[macro_use]
mod macros;

pub mod message;
pub mod types;

pub type Result<T> = result::Result<T, DnsError>;

#[derive(Debug)]
pub enum DnsError {
    ShortRead,
    SmallBuf,
    BadOpCode,
    BadRdata,
    BadRCode,
    BadRType,
    BadClass,
    TooManyCompressionPointers,
    DomainOverflow,

    #[allow(dead_code)]
    DomainUnderflow, // TODO
}
