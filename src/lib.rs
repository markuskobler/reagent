extern crate mio;

#[cfg(test)]
extern crate rustc_serialize;

use std::{io, result};
pub use server::Server;

pub mod server;
mod dns;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Dns(dns::DnsError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<dns::DnsError> for Error {
    fn from(err: dns::DnsError) -> Error {
        Error::Dns(err)
    }
}
