#![allow(dead_code,unused_imports)]
//use std::mem::transmute;
use std::{fmt, ptr};
use dns::{DnsError, Result};
use dns::types::{Class, OpCode, RCode, RRType};
use byteorder::{ByteOrder, BigEndian};

const MAX_LABEL_LEN: usize = 63;
const MAX_DOMAIN_LEN: usize = 253;

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
    pub questions: Box<[Question]>,

    // pub total_answers: u16,
    // pub total_authority: u16,
    // pub total_additionals: u16,
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

    pub fn pack(&self, buf: &mut [u8]) -> Result<usize> {
        // ID
        BigEndian::write_u16(buf, self.id);

        // Flags
        buf[2] = (self.qr as u8) << 7 |
                 (self.opcode as u8)  |
                 (self.aa as u8) << 2 |
                 (self.tc as u8) << 1 |
                 (self.rd as u8) << 0;

        buf[3] = (self.ra as u8) << 7 |
                 (self.ad as u8) << 5 |
                 (self.cd as u8) << 4 |
                 (self.rcode as u8);

        let mut offset = 12;
        let qdcount = self.questions.len() as u16;
        let ancount = 0; // todo
        let nscount = 0; // todo
        let arcount = 0; // todo

        // Counts
        BigEndian::write_u16(&mut buf[4..], qdcount);
        BigEndian::write_u16(&mut buf[6..], ancount);
        BigEndian::write_u16(&mut buf[8..], nscount);
        BigEndian::write_u16(&mut buf[10..], arcount);

        // Questions
        for q in self.questions.iter() {
            match q.pack(buf, offset) {
                Ok(o) => { offset = o },
                Err(err) => return Err(err),
            }
        }

        Ok(offset)
    }

    pub fn unpack(msg: &[u8]) -> Result<Message> {
        if msg.len() < 12 {
            return Err(DnsError::ShortRead)
        }
        let id = BigEndian::read_u16(msg);

        let opcode = try!(OpCode::unpack(msg[2] & 0x78));
        let rcode = try!(RCode::unpack(msg[3] & 0x0f));

        let mut offset = 12;
        let qdcount = BigEndian::read_u16(&msg[4..]) as usize;
        let _ancount = BigEndian::read_u16(&msg[6..]) as usize;
        let _nscount = BigEndian::read_u16(&msg[8..]) as usize;
        let _arcount = BigEndian::read_u16(&msg[10..]) as usize;

        let mut questions: Vec<Question> = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            match Question::unpack(msg, offset) {
                Ok((q, o)) => {
                    questions.push(q);
                    offset = o;
                }
                Err(err) => return Err(err),
            }
        }

        Ok(Message{
            id: id,
            opcode: opcode,
            rcode: rcode,
            qr: (msg[2]>>7) & 1 != 0,
            aa: (msg[2]>>2) & 1 != 0,
            tc: (msg[2]>>1) & 1 != 0,
            rd: (msg[2]>>0) & 1 != 0,
            ra: (msg[3]>>7) & 1 != 0,
            ad: (msg[3]>>5) & 1 != 0,
            cd: (msg[3]>>4) & 1 != 0,
            questions: questions.into_boxed_slice(),
        })
    }

    pub fn new_reply(req: &Message) -> Message {
        let mut questions = Vec::with_capacity(1);
        if req.questions.len() > 0 {
            questions.push(req.questions[0].clone());
        }

        Message{
            id: req.id,
            opcode: OpCode::QUERY,
            rcode: RCode::NOERROR,
            qr: true,
            aa: false,
            tc: false,
            rd: req.rd,
            ra: false,
            ad: false,
            cd: false,
            questions: questions.into_boxed_slice(),
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
                    0,   // todo
                    0,   // todo
                    0)); // todo

        if self.questions.len() > 0 {
            try!(write!(f, "\n;; QUESTION SECTION:\n"));
            for q in self.questions.iter() {
                try!(write!(f, ";"));
                try!(q.fmt(f));
            }
        }

        Ok(())
   }
}


#[derive(Clone)]
pub struct Question {
    pub name: QName,
    pub rrtype: RRType,
    pub class: Class,
}

/*
   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                     QNAME                     /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QTYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QCLASS                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
impl Question {

    fn pack(&self, buf: &mut [u8], mut offset: usize) -> Result<usize> {
        let len = self.name.len();
        if len + 5 > buf.len() {
            return Err(DnsError::SmallBuf)
        }
        unsafe {
            ptr::copy_nonoverlapping(self.name.inner.as_ptr(), buf.as_mut_ptr().offset(offset as isize), len);
        }
        offset += len;
        buf[offset] = 0;
        BigEndian::write_u16(&mut buf[offset+1..], self.rrtype as u16);
        BigEndian::write_u16(&mut buf[offset+3..], self.class as u16);
        return Ok(offset+5)
    }

    fn unpack(msg: &[u8], mut off: usize) -> Result<(Question, usize)> {
        let maxlen = msg.len();
        let mut off1 = off;
        let mut ptr = 0;
        let mut len = 0;
        let mut name = [0; MAX_DOMAIN_LEN + 1];
        loop {
            if off >= maxlen {
                return Err(DnsError::SmallBuf)
            }
            let c = msg[off] as usize;
            off += 1;
            match c & 0xc0 {
                0x00 => {
                    if c == 0 {
                        break
                    } else if off + c >= maxlen {
                        return Err(DnsError::SmallBuf)
                    } else if len+c > MAX_DOMAIN_LEN {
                        return Err(DnsError::DomainOverflow)
                    }
                    unsafe {
                        ptr::copy_nonoverlapping(msg.as_ptr().offset((off-1) as isize),
                                                 name.as_mut_ptr().offset(len as isize),
                                                 c+1);
                    }
                    len += c + 1;
                    off += c;
                }
                0xc0 => { // compressed response
                    if off >= maxlen {
                        return Err(DnsError::SmallBuf)
                    }
                    let c1 = msg[off] as usize;
                    off += 1;
                    if ptr == 0 {
                        off1 = off
                    }
                    off = (c^0xc0) << 8 | c1;
                    ptr += 1;
                    if ptr > 100 { // prevent endless pointer recursion
                        return Err(DnsError::TooManyCompressionPointers)
                    }
                }
                _ => return Err(DnsError::BadRdata),
            }
        }
        if ptr == 0 {
            off1 = off
        }
        Ok((Question{
            name: QName::new(&name[..len]),
            rrtype: try!(RRType::unpack(BigEndian::read_u16(&msg[off1..]))),
            class: try!(Class::unpack(BigEndian::read_u16(&msg[(off1+2)..]))),
        }, off1 + 4))
    }

}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t\t\t{:?}\t{:?}\n", self.name, self.class, self.rrtype)
    }
}

pub struct QName {
    inner: Box<[u8]>,
}

impl QName {
    fn new(buf: &[u8]) -> QName {
        QName{ inner: buf.to_owned().into_boxed_slice() }
    }

    #[inline]
    pub fn len(&self) -> usize { self.inner.len() }

    pub fn to_str(&self) -> String {
        let name = &self.inner;
        let maxlen = name.len();
        let mut buf = Vec::<u8>::with_capacity(maxlen + 1);
        if maxlen == 0 {
            buf.push(b'.');
        } else {
            let mut off = 0;
            while off < maxlen {
                let l = name[off] as usize + off + 1;
                off += 1;
                while off < l {
                    let ch = name[off];
                    match ch {
                        b'.' | b'(' | b')' | b';' | b' ' | b'@' | b'"' | b'\\' => {
                            buf.push(b'\\');
                            buf.push(ch);
                        }
                        b'\t' => {
                            buf.push(b'\\');
                            buf.push(b't');
                        }
                        b'\r' => {
                            buf.push(b'\\');
                            buf.push(b'r');
                        }
                        0...32 | 127... 255 => {
                            buf.push(b'\\');
                            buf.push(b'0'); // todo
                            buf.push(b'0');
                            buf.push(b'0');
                        }
                        _ => { buf.push(ch); }
                    }
                    off += 1;
                }
                buf.push(b'.');
            }
        }

        unsafe { String::from_utf8_unchecked(buf) }
    }

    // todo
    // pub fn from_str(name: &str) -> Result<QName> {
    //
    // }
}

impl Clone for QName {
    fn clone(&self) -> Self {
        QName { inner: self.inner.to_owned().into_boxed_slice() }
    }
}

impl fmt::Display for QName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_str().fmt(f)
    }
}


// todo tests
// 0ab0010000010000000000000377777706676f6f676c6503636f6d0000010001
