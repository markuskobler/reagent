use std::fmt;
use std::ptr::copy_nonoverlapping;
use dns::{DnsError, Result};
use dns::types::{Class, OpCode, RCode, RType};

#[allow(dead_code)]
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


#[derive(Clone)]
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
#[derive(Clone)]
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
        let mut name = [0; MAX_DOMAIN_LEN + 1];
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

    // todo
    // pub fn from_str(name: &str) -> Result<RName> {
    //
    // }
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

impl fmt::Display for RName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}


#[derive(Clone)]
pub enum RData {
    None,
    A(u8, u8, u8, u8), // replace with u32
    AAAA(u16, u16, u16, u16, u16, u16, u16, u16), // replace with u64, u64?
    RawData(Vec<u8>),
}


impl RData {

    #[allow(dead_code)]
    #[inline]
    fn len(&self) -> usize {
        match *self {
            RData::None => { 0 },
            RData::A(..) => { 4 },
            RData::AAAA(..) => { 16 },
            RData::RawData(ref v) => { v.len() }
            // todo
            // CNAME
            // TXT


            // DNAME
            // INT8
            // INT16
            // INT32
            // STR
            // APL
            // B64
            // B64_EXT
            // HEX
            // NSEC
            // TYPE
            // CLASS
            // TIME
            // PERIOD

            // not sure??
            // CERT_ALG
            // ALG
        }
    }

    fn pack(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        Ok(match *self {
            RData::None => offset,
            RData::A(a1, a2, a3, a4) => {
                unsafe{
                    write_be!(buf, offset, 4 as u16, 2);
                }
                buf[offset + 2] = a1;
                buf[offset + 3] = a2;
                buf[offset + 4] = a3;
                buf[offset + 5] = a4;
                offset + 6
            },
            RData::AAAA(a1, a2, a3, a4, a5, a6, a7, a8) => {
                unsafe{
                    write_be!(buf, offset, 16 as u16, 2);
                }
                buf[offset +  2] = (a1 >> 8) as u8;
                buf[offset +  3] = (a1 & 0xff) as u8;
                buf[offset +  4] = (a2 >> 8) as u8;
                buf[offset +  5] = (a2 & 0xff) as u8;
                buf[offset +  6] = (a3 >> 8) as u8;
                buf[offset +  7] = (a3 & 0xff) as u8;
                buf[offset +  8] = (a4 >> 8) as u8;
                buf[offset +  9] = (a4 & 0xff) as u8;
                buf[offset + 10] = (a5 >> 8) as u8;
                buf[offset + 11] = (a5 & 0xff) as u8;
                buf[offset + 12] = (a6 >> 8) as u8;
                buf[offset + 13] = (a6 & 0xff) as u8;
                buf[offset + 14] = (a7 >> 8) as u8;
                buf[offset + 15] = (a7 & 0xff) as u8;
                buf[offset + 16] = (a8 >> 8) as u8;
                buf[offset + 17] = (a8 & 0xff) as u8;
                offset + 18
            },
            RData::RawData(ref v) => {
                let len = v.len();
                unsafe {
                    write_be!(buf, offset, len as u16, 2);
                    copy_nonoverlapping(v.as_ptr(), buf.as_mut_ptr().offset((offset+2) as isize), len);
                }
                offset + 2 + len
            }

        })
    }

    // fn unpack(rtype: RType, msg: &[u8], mut off: usize) -> Result<(RName, usize)> {
    // }
}

// todo tests
// 0ab0010000010000000000000377777706676f6f676c6503636f6d0000010001
