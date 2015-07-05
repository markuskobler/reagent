use std::fmt;

use dns::{Error, Result, Class, OpCode, RCode, RType, RName, RData};

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
            return Err(Error::SmallBuf)
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

    pub fn unpack(msg: &[u8], mut offset: usize) -> Result<Message> { // TODO return remaining buffer?
        if msg.len() < 12 {
            return Err(Error::ShortRead)
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

        // TODO check remaining offset

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
                rtype: RType::A,
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
                    self.authority.len(),
                    self.additionals.len()));

        if self.questions.len() > 0 {
            try!(write!(f, "\n;; QUESTION SECTION:\n"));
            for q in self.questions.iter() {
                try!(write!(f, ";"));
                try!(q.fmt(f));
            }
        }

        if self.answers.len() > 0 {
            try!(write!(f, "\n;; ANSWER SECTION:\n"));
            for a in self.answers.iter() {
                try!(write!(f, ";"));
                try!(a.fmt(f));
            }
        }

        if self.authority.len() > 0 {
            try!(write!(f, "\n;; AUTHORITY SECTION:\n"));
            for a in self.authority.iter() {
                try!(write!(f, ";"));
                try!(a.fmt(f));
            }
        }

        if self.additionals.len() > 0 {
            try!(write!(f, "\n;; ADDITIONAL SECTION:\n"));
            for a in self.additionals.iter() {
                try!(write!(f, ";"));
                try!(a.fmt(f));
            }
        }

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
            return Err(Error::SmallBuf)
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

    #[allow(dead_code)]
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
            return Err(Error::SmallBuf)
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

        // if offset +  10 + rdlength >= msg.len() {
        //     return Err(ShortRead)
        // }

        // todo parse data type
        let data = RData::RawData(vec![]);

        Ok((Resource{
            name: name,
            rtype: rtype,
            class: class,
            ttl: ttl,
            data: data,
        }, offset + 10 + rdlength as usize))
    }

    #[allow(dead_code)]
    pub fn parse(name: &str, rtype: RType, class: Class, ttl: u32) -> Result<Resource> {
        Ok(Resource{
            name: try!(name.parse::<RName>()),
            rtype: rtype,
            class: class,
            ttl: ttl,
            data: RData::RawData(vec![]),
        })
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{:?}\t{:?}\t{:?}\n", self.name, self.ttl, self.class, self.rtype)
    }
}


#[cfg(test)] use rustc_serialize::hex::FromHex;
#[cfg(test)] use super::Error::*;
#[cfg(test)] use super::OpCode::*;
#[cfg(test)] use super::RCode::*;
#[cfg(test)] use super::RType::*;
#[cfg(test)] use super::Class::*;

#[cfg(test)]
fn q(name: &str, rtype: RType, class: Class) -> Question {
    Question::parse(name, rtype, class).unwrap()
}

#[cfg(test)]
fn r(name: &str, rtype: RType, class: Class, ttl: u32) -> Resource {
    Resource::parse(name, rtype, class, ttl).unwrap()
}

#[test]
fn unpack_message_requests() {

    fn unpack(buf: &'static str, id: u16, rcode: RCode, question: Question) {
        let msg = Message::unpack(&buf.from_hex().unwrap(), 0).unwrap();
        assert_eq!(msg.id, id);
        assert_eq!(msg.opcode, QUERY);
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
           NOERROR,
           q("www.bbc.co.uk", A, IN));

    // www.reddit.com IN A
    unpack("f13a01000001000000000000037777770672656464697403636f6d0000010001",
           61754,
           NOERROR,
           q("www.reddit.com", A, IN));

    // www.google.com IN A
    unpack("2b22010000010000000000000377777706676f6f676c6503636f6d0000010001",
           11042,
           NOERROR,
           q("www.google.com", A, IN));

    // google.com           IN MX
    // google.com           IN AAAA
    // google.com           IN ANY
    // www.microsoft.com    IN SOA
    // non.existent.domain. IN A

    // dig www.google.com with AD set
    // unpack("33be012000010000000000010377777706676f6f676c6503636f6d00000100010000291000000000000000",
    //        13246,
    //        NOERROR,
    //        Question::parse("www.google.com", A, IN));
}

#[test]
fn unpack_message_responses() {

    fn unpack(buf: &'static str, id: u16, rcode: RCode, question: Question, answers: Vec<Resource>) {
        let msg = Message::unpack(&buf.from_hex().unwrap(), 0).unwrap();
        assert_eq!(msg.id, id);
        assert_eq!(msg.opcode, QUERY);
        assert_eq!(msg.rcode, rcode);
        assert_eq!(msg.qr, true);
        assert_eq!(msg.aa, false);
        assert_eq!(msg.rd, true);
        assert_eq!(msg.ra, true);
        assert_eq!(msg.questions, vec![question]);
        assert_eq!(msg.answers, answers);
        assert_eq!(msg.authority, vec![]);
        assert_eq!(msg.additionals, vec![]);
    }

    // dig www.google.com.
    //
    // www.google.com.		188	IN	A	216.58.208.68
    unpack("2b22818000010001000000000377777706676f6f676c6503636f6d0000010001c00c00010001000000bc0004d83ad044",
           11042,
           NOERROR,
           q("www.google.com", A, IN),
           vec![r("www.google.com", A, IN, 188)]);

    // dig www.bbc.co.uk.
    //
    // www.bbc.co.uk.		167	IN	CNAME	www.bbc.net.uk.
    // www.bbc.net.uk.		58	IN	A	212.58.244.70
    // www.bbc.net.uk.		58	IN	A	212.58.244.71
    unpack("0bd081800001000300000000037777770362626302636f02756b0000010001c00c00050001000000a7000e0377777703626263036e6574c017c02b000100010000003a0004d43af446c02b000100010000003a0004d43af447",
           3024,
           NOERROR,
           q("www.bbc.co.uk", A, IN),
           vec![r("www.bbc.co.uk", CNAME, IN, 167),
                r("www.bbc.net.uk", A, IN, 58),
                r("www.bbc.net.uk", A, IN, 58)]);

    // dig www.reddit.com
    unpack("f13a81800001000f00000000037777770672656464697403636f6d0000010001c00c000100010000012b0004c629d18fc00c000100010000012b0004c629d18dc00c000100010000012b0004c629d08ec00c000100010000012b0004c629d08bc00c000100010000012b0004c629d188c00c000100010000012b0004c629d08cc00c000100010000012b0004c629d08fc00c000100010000012b0004c629d18bc00c000100010000012b0004c629d18ac00c000100010000012b0004c629d189c00c000100010000012b0004c629d089c00c000100010000012b0004c629d08ac00c000100010000012b0004c629d18ec00c000100010000012b0004c629d18cc00c000100010000012b0004c629d08d",
           61754,
           NOERROR,
           q("www.reddit.com", A, IN),
           vec![r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299),
                r("www.reddit.com", A, IN, 299)]);

}

#[test]
#[ignore]
fn pack_message_requests() {

}

#[test]
#[ignore]
fn pack_message_responses() {

}
