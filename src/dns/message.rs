use std::fmt;
use std::result;
use std::str::FromStr;
use std::ptr::copy_nonoverlapping;

use super::{DnsError, Result};
use super::types::{Class, OpCode, RCode, RType};
use super::rdata::RData;

const MAX_LABEL_LEN: usize = 63;
const MAX_DOMAIN_LEN: usize = 255;

pub struct Message {
    pub id: u16,
    pub opcode: OpCode,
    pub rcode: RCode,
    pub qr: bool,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub questions:   Vec<Question>,
    pub answers:     Vec<Resource>,
    pub authority:   Vec<Resource>,
    pub additionals: Vec<Resource>,
}

/*
   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID                       |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   OPCODE  |AA|TC|RD|RA|--|AD|CD|   RCODE   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    QDCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ANCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    NSCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    ARCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
impl Message {

    pub fn pack(&self, buf: &mut [u8], mut offset: usize) -> Result<usize> {
        if buf.len() < 12 {
            return Err(DnsError::SmallBuf)
        }

        // ID
        unsafe { write_be!(buf, offset, self.id, 2); }

        // Flags
        buf[offset + 2] = (self.qr as u8) << 7 |
                          self.opcode as u8  |
                          (self.aa as u8) << 2 |
                          (self.tc as u8) << 1 |
                          (self.rd as u8) << 0;

        buf[offset + 3] = (self.ra as u8) << 7 |
                          (self.ad as u8) << 5 |
                          (self.cd as u8) << 4 |
                          self.rcode as u8;

        // Counts
        unsafe {
            write_be!(buf, offset + 4,  self.questions.len() as u16, 2);
            write_be!(buf, offset + 6,  self.answers.len() as u16, 2);
            write_be!(buf, offset + 8,  self.authority.len() as u16, 2);
            write_be!(buf, offset + 10, self.additionals.len() as u16, 2);
            offset += 12;
        }

        // Results
        for q in self.questions.iter()   { offset = try!(q.pack(buf, offset)); }
        for a in self.answers.iter()     { offset = try!(a.pack(buf, offset)); }
        for a in self.authority.iter()   { offset = try!(a.pack(buf, offset)); }
        for a in self.additionals.iter() { offset = try!(a.pack(buf, offset)); }

        Ok(offset)
    }

    pub fn unpack(msg: &[u8], mut offset: usize) -> Result<Message> {
        if msg.len() < 12 {
            return Err(DnsError::ShortRead)
        }

        let id = unsafe{ read_be!(msg, offset, u16) };

        let flag1 = msg[offset+2];
        let opcode = try!(OpCode::unpack(flag1 & 0x78));

        let flag2 = msg[offset+3];
        let rcode = try!(RCode::unpack(flag2 & 0x0f));

        let qdcount = unsafe { read_be!(msg, offset + 4, u16) as usize };
        let ancount = unsafe { read_be!(msg, offset + 6, u16) as usize };
        let nscount = unsafe { read_be!(msg, offset + 8, u16) as usize };
        let arcount = unsafe { read_be!(msg, offset + 10, u16) as usize };
        offset += 12;

        let mut questions: Vec<Question> = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            match Question::unpack(msg, offset) {
                Err(err) => return Err(err),
                Ok((q, o)) => {
                    questions.push(q);
                    offset = o;
                }
            }
        }

        // TODO check for truncation bit?

        let mut answers: Vec<Resource> = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            match Resource::unpack(msg, offset) {
                Err(err) => return Err(err),
                Ok((a, o)) => {
                    answers.push(a);
                    offset = o;
                }
            }
        }

        let mut authority: Vec<Resource> = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            match Resource::unpack(msg, offset) {
                Err(err) => return Err(err),
                Ok((a, o)) => {
                    authority.push(a);
                    offset = o;
                }
            }
        }

        let mut additionals: Vec<Resource> = Vec::with_capacity(arcount);
        for _ in 0..arcount {
            match Resource::unpack(msg, offset) {
                Err(err) => return Err(err),
                Ok((a, o)) => {
                    additionals.push(a);
                    offset = o;
                }
            }
        }

        Ok(Message{
            id: id,
            opcode: opcode,
            rcode: rcode,
            qr: (flag1 >> 7) & 1 != 0,
            aa: (flag1 >> 2) & 1 != 0,
            tc: (flag1 >> 1) & 1 != 0,
            rd: (flag1 >> 0) & 1 != 0,
            ra: (flag2 >> 7) & 1 != 0,
            ad: (flag2 >> 5) & 1 != 0,
            cd: (flag2 >> 4) & 1 != 0,
            questions: questions,
            answers: answers,
            authority: authority,
            additionals: additionals,
        })
    }

    pub fn new_reply(req: &Message) -> Message {
        let mut questions = Vec::with_capacity(1);

        let mut answers = Vec::with_capacity(0); // TODO remove me

        if req.questions.len() > 0 {
            let ref q = req.questions[0];

            questions.push(q.clone());

            // TODO hardcoded hack
            let resource = Resource{
                name: q.name.clone(),
                rtype: RType::AAAA,
                class: q.class,
                ttl: 300,
                data: RData::A(0xd8, 0x3a, 0xd0, 0x2e),
            };
            answers.push(resource);
        }

        Message{
            id: req.id,
            opcode: OpCode::QUERY,
            rcode: RCode::NOERROR,
            qr: true,
            aa: false,
            tc: false,
            rd: req.rd,
            ra: true,
            ad: false,
            cd: false,
            questions: questions,
            answers: answers,
            authority: vec![],
            additionals: vec![],
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, ";; ->>HEADER<<- opcode: {:?}, status: {:?}, id: {}\n;; flags:",
                    self.opcode, self.rcode, self.id));

        if self.qr { try!(write!(f, " qr")); }
        if self.aa { try!(write!(f, " aa")); }
        if self.tc { try!(write!(f, " tc")); }
        if self.rd { try!(write!(f, " rd")); }
        if self.ra { try!(write!(f, " ra")); }
        if self.ad { try!(write!(f, " ad")); }
        if self.cd { try!(write!(f, " cd")); }

        try!(write!(f, "; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
                    self.questions.len(),
                    self.answers.len(),
                    0,   // todo
                    0)); // todo

        if self.questions.len() > 0 {
            try!(write!(f, "\n;; QUESTION SECTION:\n"));
            for q in self.questions.iter() {
                try!(write!(f, ";"));
                try!(q.fmt(f));
            }
        }

        // if self.answers.len() > 0 {
        //     try!(write!(f, "\n;; ANSWER SECTION:\n"));
        //     for a in self.answers.iter() {
        //         try!(write!(f, ";"));
        //         try!(a.fmt(f));
        //     }
        // }

        // if self.authority.len() > 0 {
        //     try!(write!(f, "\n;; AUTHORITY SECTION:\n"));
        //     for a in self.authority.iter() {
        //         try!(write!(f, ";"));
        //         try!(a.fmt(f));
        //     }
        // }

        // if self.additionals.len() > 0 {
        //     try!(write!(f, "\n;; ADDITIONAL SECTION:\n"));
        //     for a in self.additionals.iter() {
        //         try!(write!(f, ";"));
        //         try!(a.fmt(f));
        //     }
        // }

        Ok(())
   }
}


#[derive(Clone, PartialEq)]
pub struct Question {
    pub name: RName,
    pub rtype: RType,
    pub class: Class,
}

/*
   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                      NAME                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     CLASS                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
impl Question {

    fn pack(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        let offset = try!(self.name.pack(buf, offset));
        if offset + 4 > buf.len() {
            return Err(DnsError::SmallBuf)
        }
        unsafe {
            write_be!(buf, offset, self.rtype as u16, 2);
            write_be!(buf, offset+2, self.class as u16, 2);
        }
        return Ok(offset+4)
    }

    fn unpack(msg: &[u8], offset: usize) -> Result<(Question, usize)> {
        match RName::unpack(msg, offset) {
            Err(e) => Err(e),
            Ok((name, offset)) => {
                Ok((Question{
                    name: name,
                    rtype: try!(RType::unpack(unsafe { read_be!(msg, offset, u16) })),
                    class: try!(Class::unpack(unsafe { read_be!(msg, offset+2, u16) })),
                }, offset + 4))
            }
        }
    }

    pub fn parse(name: &str, rtype: RType, class: Class) -> Result<Question> {
        Ok(Question{
            name: try!(name.parse::<RName>()),
            rtype: rtype,
            class: class,
        })
    }
}

impl fmt::Debug for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {:?} {:?}", self.name, self.class, self.rtype)
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t\t\t{:?}\t{:?}\n", self.name, self.class, self.rtype)
    }
}


/*
     0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                      NAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                                               /
    /                     RDATA                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    pub name: RName,
    pub rtype: RType,
    pub class: Class,
    pub ttl: u32,
    pub data: RData,
}

impl Resource {

    fn pack(&self, buf: &mut [u8], mut offset: usize) -> Result<usize> {
        offset = try!(self.name.pack(buf, offset));
        if offset + 8 > buf.len() {
            return Err(DnsError::SmallBuf)
        }
        unsafe {
            write_be!(buf, offset, self.rtype as u16, 2);
            write_be!(buf, offset + 2, self.class as u16, 2);
            write_be!(buf, offset + 4, self.ttl, 4);
        }
        Ok(try!(self.data.pack(buf, offset+8)))
    }

    fn unpack(msg: &[u8], offset: usize) -> Result<(Resource, usize)> {
        let (name, offset) = try!(RName::unpack(msg, offset));
        let rtype = try!(RType::unpack(unsafe { read_be!(msg, offset, u16) }));
        let class = try!(Class::unpack(unsafe { read_be!(msg, offset + 2, u16) }));
        let ttl = unsafe { read_be!(msg, offset + 4, u32 ) };
        let rdlength = unsafe { read_be!(msg, offset + 8, u16) };

        // todo parse data type

        Ok((Resource{
            name: name,
            rtype: rtype,
            class: class,
            ttl: ttl,
            data: RData::RawData(vec![]), // todo?
        }, offset + 10 + rdlength as usize))
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{:?}\t{:?}\t{:?}\n", self.name, self.ttl, self.class, self.rtype)
    }
}


#[derive(PartialEq)]
pub struct RName {
    inner: Vec<u8>,
}

impl RName {

    #[inline]
    pub fn len(&self) -> usize { self.inner.len() }

    fn pack(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        let len = self.len();
        if len + 1 > buf.len() {
            return Err(DnsError::SmallBuf)
        }
        unsafe {
            copy_nonoverlapping(self.inner.as_ptr(), buf.as_mut_ptr().offset(offset as isize), len);
        }
        buf[offset + len] = 0;
        Ok(offset + len + 1)
    }

    fn unpack(msg: &[u8], mut offset: usize) -> Result<(RName, usize)> {
        let maxlen = msg.len();
        let mut off1 = offset;
        let mut ptr = 0;
        let mut len = 0;
        let mut name = [0; MAX_DOMAIN_LEN-1]; // Ingore last byte \0
        loop {
            if offset >= maxlen {
                return Err(DnsError::SmallBuf)
            }
            let c = msg[offset] as usize;
            offset += 1;
            match c & 0xc0 {
                0x00 => {
                    if c == 0 {
                        break
                    } else if len + c > MAX_DOMAIN_LEN {
                        return Err(DnsError::DomainOverflow)
                    } else if offset + c >= maxlen {
                        return Err(DnsError::SmallBuf)
                    }
                    unsafe {
                        copy_nonoverlapping(msg.as_ptr().offset((offset-1) as isize),
                                                 name.as_mut_ptr().offset(len as isize),
                                                 c+1);
                    }
                    len += c + 1;
                    offset += c;
                }
                0xc0 => { // compressed response
                    if offset >= maxlen {
                        return Err(DnsError::SmallBuf)
                    }
                    let c1 = msg[offset] as usize;
                    offset += 1;
                    if ptr == 0 {
                        off1 = offset
                    }
                    offset = (c^0xc0) << 8 | c1;
                    ptr += 1;
                    if ptr > 100 { // prevent endless pointer recursion
                        return Err(DnsError::TooManyCompressionPointers)
                    }
                }
                _ => return Err(DnsError::BadRdata),
            }
        }
        if ptr == 0 {
            off1 = offset
        }
        Ok((RName{inner: name[..len].to_vec()}, off1))
    }

    pub fn to_string(&self) -> String {
        let name = &self.inner;
        let maxlen = name.len();
        let mut buf = Vec::with_capacity(maxlen + 1);
        if maxlen == 0 {
            buf.push(b'.');
        } else {
            let mut off = 0;
            while off < maxlen {
                let l = name[off] as usize + off + 1;
                off += 1;
                while off < l {
                    match name[off] {
                        b'\t' => { buf.push(b'\\'); buf.push(b't'); }
                        b'\r' => { buf.push(b'\\'); buf.push(b'r'); }
                        b'\n' => { buf.push(b'\\'); buf.push(b'n'); }
                        c @ b'.' | c @ b'(' | c @ b')' | c @ b';' | c @ b' ' | c @ b'@' | c @ b'"' | c @ b'\\' => {
                            buf.push(b'\\'); buf.push(c);
                        }
                        c @ 0...9 => {
                            buf.push(b'\\');
                            buf.push(b'0');
                            buf.push(b'0');
                            buf.push(b'0' + (c % 10));
                        }
                        c @ 10...32 => {
                            buf.push(b'\\');
                            buf.push(b'0');
                            buf.push(b'0' + ((c / 10) % 10));
                            buf.push(b'0' + (c % 10));
                        }
                        c @ 127...255 => {
                            buf.push(b'\\');
                            buf.push(b'0' + ((c / 100) % 10));
                            buf.push(b'0' + ((c / 10) % 10));
                            buf.push(b'0' + (c % 10));
                        }
                        c => { buf.push(c); }
                    }
                    off += 1;
                }
                buf.push(b'.');
            }
            if buf.capacity() > buf.len() + 5 {
                buf.shrink_to_fit();
            }
        }
        unsafe { String::from_utf8_unchecked(buf) }
    }
}

impl FromStr for RName {
    type Err = DnsError;

    fn from_str(s: &str) -> result::Result<RName, DnsError> {
        let maxlen = s.len();
        if maxlen > MAX_DOMAIN_LEN * 4 { // allow for esacped
            return Err(DnsError::DomainOverflow)
        } else if maxlen == 0 {
            return Ok(RName{inner: vec![]})
        }

        let bytes = s.as_bytes();

        if maxlen == 1 && bytes[0] == b'.' {
            return Ok(RName{inner: vec![]})
        }

        let mut name = [0 as u8; MAX_DOMAIN_LEN - 1];
        let mut off = 1;
        let mut label = 0;
        let mut l = 0;

        while l < maxlen {
            if off > MAX_DOMAIN_LEN - 1 {
                return Err(DnsError::DomainOverflow)
            }
            match bytes[l] {
                b'.' => {
                    if label > MAX_LABEL_LEN {
                        return Err(DnsError::DomainOverflow)
                    } else if label == 0 {
                        return Err(DnsError::EmptyLabel)
                    }
                    name[off-label-1] = label as u8;
                    label = 0;
                }
                b'\\' => {
                    l += 1;
                    if l >= maxlen {
                        return Err(DnsError::BadEscape)
                    }
                    name[off] = match bytes[l] {
                        n0 @ b'0' ... b'9' => {
                            if l+2 > maxlen {
                                return Err(DnsError::BadEscape)
                            }
                            l += 1;
                            let n1 = bytes[l];
                            if n1 < b'0' || n1 > b'9' {
                                return Err(DnsError::BadEscape)
                            }
                            l += 1;
                            let n2 = bytes[l];
                            if n2 < b'0' || n2 > b'9' {
                                return Err(DnsError::BadEscape)
                            }

                            (n0 - b'0') * 100 +
                            (n1 - b'0') * 10 +
                            (n2 - b'0')
                        }
                        b't' => b'\t',
                        b'r' => b'\r',
                        b'n' => b'\n',
                        ech  =>  ech,
                    };
                    label += 1;
                }
                ch => {
                    name[off] = ch;
                    label += 1;
                }
            }
            l += 1;
            off += 1;
        }
        if label == 0 {
            off -= 1;
        } else {
            if label > MAX_LABEL_LEN {
                return Err(DnsError::DomainOverflow)
            } else if label == 0 {
                return Err(DnsError::EmptyLabel)
            }
            name[off-label-1] = label as u8;
        }
        Ok(RName{inner: name[..off].to_vec()})
    }
}

// TODO
// impl Iterator for RName {
//     type Item = String;
//     fn next(&self) -> Option<String> {
//         None()
//     }
// }

impl Clone for RName {
    fn clone(&self) -> Self {
        RName { inner: self.inner.to_owned() }
    }
}

impl fmt::Debug for RName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

impl fmt::Display for RName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}


#[cfg(test)] use rustc_serialize::hex::FromHex;
#[cfg(test)] use super::DnsError::*;

#[test]
fn parse_valid_rnames_from_str() {
    assert_eq!(RName::from_str("").unwrap().inner, vec![]);
    assert_eq!(RName::from_str(".").unwrap().inner, vec![]);

    assert_eq!(RName::from_str("www.google.com").unwrap().inner,
               vec![3, b'w', b'w', b'w',
                    6, b'g', b'o', b'o', b'g', b'l', b'e',
                    3, b'c', b'o', b'm']);

    assert_eq!(RName::from_str("www.google.com.").unwrap().inner,
               vec![3, b'w', b'w', b'w',
                    6, b'g', b'o', b'o', b'g', b'l', b'e',
                    3, b'c', b'o', b'm']);

    RName::from_str("thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com").unwrap();

    assert_eq!(RName::from_str("\\..").unwrap().inner, vec![1, b'.']);
    assert_eq!(RName::from_str("\\001.").unwrap().inner, vec![1, 0x01]);

    assert_eq!(RName::from_str("m\\n\\r\\t.com").unwrap().inner,
               vec![4, b'm', b'\n', b'\r', b'\t',
                    3, b'c', b'o', b'm']);
}

#[test]
fn parse_invalid_rnames_from_str() {
    assert_eq!(RName::from_str("example..com"), Err(EmptyLabel));
    assert_eq!(RName::from_str("example.com\\"), Err(BadEscape));
    assert_eq!(RName::from_str("thelongestinvaliddomainnameintheworldandthensomeandthensomemoreandmore.com"), Err(DomainOverflow));

}


#[test]
fn unpack_message_requests() {

    fn unpack(buf: &'static str, id: u16, rcode: RCode, question: Question) {
        let msg = Message::unpack(&buf.from_hex().unwrap(), 0).unwrap();
        assert_eq!(msg.id, id);
        assert_eq!(msg.opcode, OpCode::QUERY);
        assert_eq!(msg.rcode, rcode);
        assert_eq!(msg.qr, false);
        assert_eq!(msg.aa, false);
        assert_eq!(msg.rd, true);
        assert_eq!(msg.ra, false);
        assert_eq!(msg.questions, vec![question]);
        assert_eq!(msg.answers, vec![]);
        assert_eq!(msg.authority, vec![]);
        assert_eq!(msg.additionals, vec![]);
    }

    // www.bbc.co.uk IN A
    unpack("0bd001000001000000000000037777770362626302636f02756b0000010001",
           3024,
           RCode::NOERROR,
           Question::parse("www.bbc.co.uk", RType::A, Class::IN).unwrap());

    // www.reddit.com IN A
    unpack("f13a01000001000000000000037777770672656464697403636f6d0000010001",
           61754,
           RCode::NOERROR,
           Question::parse("www.reddit.com", RType::A, Class::IN).unwrap());

    // www.google.com IN A
    unpack("2b22010000010000000000000377777706676f6f676c6503636f6d0000010001",
           11042,
           RCode::NOERROR,
           Question::parse("www.google.com", RType::A, Class::IN).unwrap());

    // google.com           IN MX
    // google.com           IN AAAA
    // google.com           IN ANY
    // www.microsoft.com    IN SOA
    // non.existent.domain. IN A
}

#[test]
fn unpack_message_responses() {

    let msg = Message::unpack(&"2b22818000010001000000000377777706676f6f676c6503636f6d0000010001c00c00010001000000bc0004d83ad044".from_hex().unwrap(), 0).unwrap();
    assert_eq!(msg.id, 11042 as u16);
    assert_eq!(msg.opcode, OpCode::QUERY);
    assert_eq!(msg.rcode, RCode::NOERROR);
    assert_eq!(msg.qr, true);
    assert_eq!(msg.aa, false);
    assert_eq!(msg.rd, true);
    assert_eq!(msg.ra, true);
    assert_eq!(msg.questions.len(), 1);
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.authority.len(), 0);
    assert_eq!(msg.additionals.len(), 0);

    // ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11042
    // ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    // ;; QUESTION SECTION:
    // ;www.google.com.			IN	A
    // ;; ANSWER SECTION:
    // www.google.com.		188	IN	A	216.58.208.68

    // ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3024
    // ;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0
    // ;; QUESTION SECTION:
    // ;www.bbc.co.uk.			IN	A
    // ;; ANSWER SECTION:
    // www.bbc.co.uk.		167	IN	CNAME	www.bbc.net.uk.
    // www.bbc.net.uk.		58	IN	A	212.58.244.70
    // www.bbc.net.uk.		58	IN	A	212.58.244.71
    let msg = Message::unpack(&"0bd081800001000300000000037777770362626302636f02756b0000010001c00c00050001000000a7000e0377777703626263036e6574c017c02b000100010000003a0004d43af446c02b000100010000003a0004d43af447".from_hex().unwrap(), 0).unwrap();
    assert_eq!(msg.id, 3024 as u16);
    assert_eq!(msg.opcode, OpCode::QUERY);
    assert_eq!(msg.rcode, RCode::NOERROR);
    assert_eq!(msg.qr, true);
    assert_eq!(msg.aa, false);
    assert_eq!(msg.rd, true);
    assert_eq!(msg.ra, true);
    assert_eq!(msg.questions.len(), 1);
    assert_eq!(msg.answers.len(), 3);
    assert_eq!(msg.authority.len(), 0);
    assert_eq!(msg.additionals.len(), 0);


    // dig www.redit.com
    let msg = Message::unpack(&"f13a81800001000f00000000037777770672656464697403636f6d0000010001c00c000100010000012b0004c629d18fc00c000100010000012b0004c629d18dc00c000100010000012b0004c629d08ec00c000100010000012b0004c629d08bc00c000100010000012b0004c629d188c00c000100010000012b0004c629d08cc00c000100010000012b0004c629d08fc00c000100010000012b0004c629d18bc00c000100010000012b0004c629d18ac00c000100010000012b0004c629d189c00c000100010000012b0004c629d089c00c000100010000012b0004c629d08ac00c000100010000012b0004c629d18ec00c000100010000012b0004c629d18cc00c000100010000012b0004c629d08d".from_hex().unwrap(), 0).unwrap();
    assert_eq!(msg.id, 61754 as u16);
    assert_eq!(msg.opcode, OpCode::QUERY);
    assert_eq!(msg.rcode, RCode::NOERROR);
    assert_eq!(msg.qr, true);
    assert_eq!(msg.aa, false);
    assert_eq!(msg.rd, true);
    assert_eq!(msg.ra, true);
    assert_eq!(msg.questions.len(), 1);
    assert_eq!(msg.answers.len(), 15);
    assert_eq!(msg.authority.len(), 0);
    assert_eq!(msg.additionals.len(), 0);
}

#[test]
#[ignore]
fn pack_message_requests() {

}

#[test]
#[ignore]
fn pack_message_responses() {

}
