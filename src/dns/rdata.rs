use std::ptr::copy_nonoverlapping;

use dns::Result;

#[derive(Clone, PartialEq, Debug)]
pub enum RData {
    None,
    A(u8, u8, u8, u8), // replace with u32 or u16, u16
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

    pub fn pack(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
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
