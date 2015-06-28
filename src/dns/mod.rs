#[allow(unused_imports)]
use std::{io, result};

pub use dns::message::Message;

pub mod message;
pub mod types;

pub type Result<T> = result::Result<T, DnsError>;

#[derive(Debug)]
pub enum DnsError {
//    Io(io::Error),
    ShortRead,
    SmallBuf,
    BadOpCode,
    BadRdata,
    BadRCode,
    BadRRType,
    BadClass,
    TooManyCompressionPointers,
    DomainOverflow,
//    DomainUnderflow,
}


// impl From<io::Error> for DnsError {
//     fn from(err: io::Error) -> DnsError {
//         DnsError::Io(err)
//     }
// }
