use std::result;

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

const MAX_LABEL_LEN: usize = 63;
const MAX_DOMAIN_LEN: usize = 255;

pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
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
