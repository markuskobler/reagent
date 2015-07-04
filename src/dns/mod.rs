#[allow(unused_imports)]
use std::{io, result};

pub use dns::message::Message;

#[macro_use]
mod macros;

pub mod message;
pub mod types;
pub mod rdata;

pub type Result<T> = result::Result<T, DnsError>;

#[derive(Debug, PartialEq)]
pub enum DnsError {
    ShortRead,
    SmallBuf,
    BadOpCode,
    BadRdata,
    BadRCode,
    BadRType,
    BadClass,
    BadEscape,
    TooManyCompressionPointers,
    DomainOverflow,
    EmptyLabel,
}
