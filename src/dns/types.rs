use dns::{DnsError, Result};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpCode {
    QUERY   = 0x00,
    IQUERY  = 0x08,
    STATUS  = 0x10,
    NOTIFY  = 0x20,
    UPDATE  = 0x28,
}

impl OpCode {
    #[inline]
    pub fn unpack(v: u8) -> Result<OpCode> {
        Ok(match v {
            0x00 => OpCode::QUERY,
            0x08 => OpCode::IQUERY,
            0x10=> OpCode::STATUS,
            0x20 => OpCode::NOTIFY,
            0x28 => OpCode::UPDATE,
            _   => return Err(DnsError::BadOpCode),
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RCode {
    NOERROR  = 0x00,
    FORMERR  = 0x01,
    SERVFAIL = 0x02,
    NXDOMAIN = 0x03,
    NOTIMPL  = 0x04,
    REFUSED  = 0x05,
    YXDOMAIN = 0x06,
    YXRRSET  = 0x07,
    NXRRSET  = 0x08,
    NOTAUTH  = 0x09,
    NOTZONE  = 0x0a,
    BADSIG   = 0x10, // or BADVERS ??
    BADKEY   = 0x11,
    BADTIME  = 0x12,
    BADMODE  = 0x13,
    BADNAME  = 0x14,
    BADALG   = 0x15,
    BADTRUNC = 0x16,
}

impl RCode {
    #[inline]
    pub fn unpack(v: u8) -> Result<RCode> {
        Ok(match v {
            0x00 => RCode::NOERROR,
            0x01 => RCode::FORMERR,
            0x02 => RCode::SERVFAIL,
            0x03 => RCode::NXDOMAIN,
            0x04 => RCode::NOTIMPL,
            0x05 => RCode::REFUSED,
            0x06 => RCode::YXDOMAIN,
            0x07 => RCode::YXRRSET,
            0x08 => RCode::NXRRSET,
            0x09 => RCode::NOTAUTH,
            0x0a => RCode::NOTZONE,
            0x10 => RCode::BADSIG,
            0x11 => RCode::BADKEY,
            0x12 => RCode::BADTIME,
            0x13 => RCode::BADMODE,
            0x14 => RCode::BADNAME,
            0x15 => RCode::BADALG,
            0x16 => RCode::BADTRUNC,
            _    => return Err(DnsError::BadRCode),
        })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Class {
    IN   = 0x01, // INET
    CH   = 0x03, // ClassCHAOS
    HS   = 0x04, // HESIOD
    NONE = 0xfe,
    ANY  = 0xff,
}

impl Class {
    #[inline]
    pub fn unpack(v: u16) -> Result<Class> {
        Ok(match v {
            0x01 => Class::IN,
            0x03 => Class::CH,
            0x04 => Class::HS,
            0xfe => Class::NONE,
            0xff => Class::ANY,
            _ => return Err(DnsError::BadClass)
        })
    }
}

#[repr(u16)]
#[derive(Debug,Clone, Copy, PartialEq)]
pub enum RRType {
    NONE       = 0x0000,
    A          = 0x0001,
    NS         = 0x0002,
    MD         = 0x0003,
    MF         = 0x0004,
    CNAME      = 0x0005,
    SOA        = 0x0006,
    MB         = 0x0007,
    MG         = 0x0008,
    MR         = 0x0009,
    NULL       = 0x000A,
    WKS        = 0x000B,
    PTR        = 0x000C,
    HINFO      = 0x000D,
    MINFO      = 0x000E,
    MX         = 0x000F,
    TXT        = 0x0010,
    RP         = 0x0011,
    AFSDB      = 0x0012,
    X25        = 0x0013,
    ISDN       = 0x0014,
    RT         = 0x0015,
    NSAP       = 0x0016,
    NSAPPTR    = 0x0017,
    SIG        = 0x0018,
    KEY        = 0x0019,
    PX         = 0x001A,
    GPOS       = 0x001B,
    AAAA       = 0x001C,
    LOC        = 0x001D,
    NXT        = 0x001E,
    EID        = 0x001F,
    NIMLOC     = 0x0020,
    SRV        = 0x0021,
    ATMA       = 0x0022,
    NAPTR      = 0x0023,
    KX         = 0x0024,
    CERT       = 0x0025,
    DNAME      = 0x0026,
    SINK       = 0x0027,
    OPT        = 0x0028,
    APL        = 0x0029,
    DS         = 0x002A,
    SSHFP      = 0x002B,
    IPSECKEY   = 0x002C,
    RRSIG      = 0x002D,
    NSEC       = 0x002E,
    DNSKEY     = 0x002F,
    DHCID      = 0x0030,
    NSEC3      = 0x0031,
    NSEC3PARAM = 0x0032,
    TLSA       = 0x0033,
    HIP        = 0x0036,
    NINFO      = 0x0037,
    RKEY       = 0x0038,
    TALINK     = 0x0039,
    CDS        = 0x003A,
    CDNSKEY    = 0x003B,
    OPENPGPKEY = 0x003C,
    SPF        = 0x0063,
    UINFO      = 0x0064,
    UID        = 0x0065,
    GID        = 0x0066,
    UNSPEC     = 0x0067,
    NID        = 0x0068,
    L32        = 0x0069,
    L64        = 0x006A,
    LP         = 0x006B,
    EUI48      = 0x006C,
    EUI64      = 0x006D,

    TKEY       = 0x00F9,
    TSIG       = 0x00FA,

    IXFR       = 0x00FB,
    AXFR       = 0x00FC,
    MAILB      = 0x00FD,
    MAILA      = 0x00FE,
    ANY        = 0x00FF,

    URI        = 0x0100,
    CAA        = 0x0101,
    TA         = 0x8000,
    DLV        = 0x8001,
    Reserved   = 0xFFFF,
}

impl RRType {
    #[inline]
    pub fn unpack(v: u16) -> Result<RRType> {
        Ok(match v {
            0x0000 => RRType::NONE, // check if valid?
            0x0001 => RRType::A,
            0x0002 => RRType::NS,
            0x0003 => RRType::MD,
            0x0004 => RRType::MF,
            0x0005 => RRType::CNAME,
            0x0006 => RRType::SOA,
            0x0007 => RRType::MB,
            0x0008 => RRType::MG,
            0x0009 => RRType::MR,
            0x000A => RRType::NULL,
            0x000B => RRType::WKS,
            0x000C => RRType::PTR,
            0x000D => RRType::HINFO,
            0x000E => RRType::MINFO,
            0x000F => RRType::MX,
            0x0010 => RRType::TXT,
            0x0011 => RRType::RP,
            0x0012 => RRType::AFSDB,
            0x0013 => RRType::X25,
            0x0014 => RRType::ISDN,
            0x0015 => RRType::RT,
            0x0016 => RRType::NSAP,
            0x0017 => RRType::NSAPPTR,
            0x0018 => RRType::SIG,
            0x0019 => RRType::KEY,
            0x001A => RRType::PX,
            0x001B => RRType::GPOS,
            0x001C => RRType::AAAA,
            0x001D => RRType::LOC,
            0x001E => RRType::NXT,
            0x001F => RRType::EID,
            0x0020 => RRType::NIMLOC,
            0x0021 => RRType::SRV,
            0x0022 => RRType::ATMA,
            0x0023 => RRType::NAPTR,
            0x0024 => RRType::KX,
            0x0025 => RRType::CERT,
            0x0026 => RRType::DNAME,
            0x0027 => RRType::SINK,
            0x0028 => RRType::OPT,
            0x0029 => RRType::APL,
            0x002A => RRType::DS,
            0x002B => RRType::SSHFP,
            0x002C => RRType::IPSECKEY,
            0x002D => RRType::RRSIG,
            0x002E => RRType::NSEC,
            0x002F => RRType::DNSKEY,
            0x0030 => RRType::DHCID,
            0x0031 => RRType::NSEC3,
            0x0032 => RRType::NSEC3PARAM,
            0x0033 => RRType::TLSA,
            0x0036 => RRType::HIP,
            0x0037 => RRType::NINFO,
            0x0038 => RRType::RKEY,
            0x0039 => RRType::TALINK,
            0x003A => RRType::CDS,
            0x003B => RRType::CDNSKEY,
            0x003C => RRType::OPENPGPKEY,
            0x0063 => RRType::SPF,
            0x0064 => RRType::UINFO,
            0x0065 => RRType::UID,
            0x0066 => RRType::GID,
            0x0067 => RRType::UNSPEC,
            0x0068 => RRType::NID,
            0x0069 => RRType::L32,
            0x006A => RRType::L64,
            0x006B => RRType::LP,
            0x006C => RRType::EUI48,
            0x006D => RRType::EUI64,

            0x00F9 => RRType::TKEY,
            0x00FA => RRType::TSIG,

            // QType only
            0x00FB => RRType::IXFR,
            0x00FC => RRType::AXFR,
            0x00FD => RRType::MAILB,
            0x00FE => RRType::MAILA,
            0x00FF => RRType::ANY,

            0x0100 => RRType::URI,
            0x0101 => RRType::CAA,
            0x8000 => RRType::TA,
            0x8001 => RRType::DLV,

            0xFFFF => RRType::Reserved,

            _ => return Err(DnsError::BadRRType)
        })
    }
}
