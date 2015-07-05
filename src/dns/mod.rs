#[allow(unused_imports)]
use std::{io, result};

pub use dns::types::{OpCode, RCode, RType, Class};
pub use dns::rname::RName;
pub use dns::rdata::RData;
pub use dns::message::Message;

#[macro_use]
mod macros;

pub mod types;
pub mod rname;
pub mod rdata;
pub mod message;

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
