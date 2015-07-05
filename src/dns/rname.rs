use std::fmt;
use std::result;
use std::ptr::copy_nonoverlapping;
use std::iter::FromIterator;
use std::str::FromStr;

use dns::{Result, Error};
use dns::{MAX_LABEL_LEN, MAX_DOMAIN_LEN};

#[derive(PartialEq)]
pub struct RName {
    inner: Vec<u8>,
}

impl RName {

    #[inline]
    pub fn len(&self) -> usize { self.inner.len() }

    #[allow(dead_code)]
    pub fn to_vec(&self) -> Vec<String> {
        Vec::from_iter(self.into_iter())
    }

    pub fn pack(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        let len = self.len();
        if len + 1 > buf.len() {
            return Err(Error::SmallBuf)
        }
        unsafe {
            copy_nonoverlapping(self.inner.as_ptr(), buf.as_mut_ptr().offset(offset as isize), len);
        }
        buf[offset + len] = 0;
        Ok(offset + len + 1)
    }

    pub fn unpack(msg: &[u8], mut offset: usize) -> Result<(RName, usize)> {
        let maxlen = msg.len();
        let mut off1 = offset;
        let mut ptr = 0;
        let mut len = 0;
        let mut name = [0; MAX_DOMAIN_LEN-1]; // Ingore last byte \0
        loop {
            if offset >= maxlen {
                return Err(Error::SmallBuf)
            }
            let c = msg[offset] as usize;
            offset += 1;
            match c & 0xc0 {
                0x00 => {
                    if c == 0 {
                        break
                    } else if len + c > MAX_DOMAIN_LEN {
                        return Err(Error::DomainOverflow)
                    } else if offset + c >= maxlen {
                        return Err(Error::SmallBuf)
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
                        return Err(Error::SmallBuf)
                    }
                    let c1 = msg[offset] as usize;
                    offset += 1;
                    if ptr == 0 {
                        off1 = offset
                    }
                    offset = (c^0xc0) << 8 | c1;
                    ptr += 1;
                    if ptr > 100 { // prevent endless pointer recursion
                        return Err(Error::TooManyCompressionPointers)
                    }
                }
                _ => return Err(Error::BadRdata),
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
                off = write_label(&mut buf, &name, off + 1, name[off] as usize);
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
    type Err = Error;

    fn from_str(s: &str) -> result::Result<RName, Error> {
        let maxlen = s.len();
        if maxlen > MAX_DOMAIN_LEN * 4 { // allow for esacped
            return Err(Error::DomainOverflow)
        } else if maxlen == 0 {
            return Ok(RName{inner: vec![]})
        }

        let bytes = s.as_bytes();

        if maxlen == 1 && bytes[0] == b'.' {
            return Ok(RName{inner: vec![]})
        }

        let mut name = [0 as u8; MAX_DOMAIN_LEN - 1];
        let mut label = 0;
        let mut off = 1;
        let mut l = 0;

        while l < maxlen {
            if off > MAX_DOMAIN_LEN - 1 {
                return Err(Error::DomainOverflow)
            }
            match bytes[l] {
                b'.' => {
                    if label > MAX_LABEL_LEN {
                        return Err(Error::DomainOverflow)
                    } else if label == 0 {
                        return Err(Error::EmptyLabel)
                    }
                    name[off-label-1] = label as u8;
                    label = 0;
                }
                b'\\' => {
                    l += 1;
                    if l >= maxlen {
                        return Err(Error::BadEscape)
                    }
                    name[off] = match bytes[l] {
                        n0 @ b'0' ... b'9' => {
                            if l+2 > maxlen {
                                return Err(Error::BadEscape)
                            }
                            l += 1;
                            let n1 = bytes[l];
                            if n1 < b'0' || n1 > b'9' {
                                return Err(Error::BadEscape)
                            }
                            l += 1;
                            let n2 = bytes[l];
                            if n2 < b'0' || n2 > b'9' {
                                return Err(Error::BadEscape)
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
                return Err(Error::DomainOverflow)
            } else if label == 0 {
                return Err(Error::EmptyLabel)
            }
            name[off-label-1] = label as u8;
        }
        Ok(RName{inner: name[..off].to_vec()})
    }
}

pub struct RNameIter<'a> {
    name: &'a [u8],
    off: usize,
}

impl<'a> Iterator for RNameIter<'a> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let pos = self.off;
        if pos >= self.name.len() {
            return None
        }
        let label = self.name[pos] as usize;
        let mut buf = Vec::with_capacity(label);

        self.off = write_label(&mut buf, &self.name, pos + 1, label);

        Some(unsafe { String::from_utf8_unchecked( buf ) })
    }
}


#[inline]
fn write_label(buf: &mut Vec<u8>, name: &[u8], mut off: usize, mut len: usize) -> usize {
    len += off;

    while off < len {
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

    off
}

impl<'a> IntoIterator for &'a RName {
    type Item = String;
    type IntoIter = RNameIter<'a>;

    fn into_iter(self) -> RNameIter<'a> {
        RNameIter{ name: &self.inner, off: 0 }
    }
}

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

#[cfg(test)] use super::Error::*;

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
fn iterate_rnames() {
    assert_eq!(RName::from_str("www.google.com").unwrap().to_vec(),
               vec!["www".to_string(),
                    "google".to_string(),
                    "com".to_string()])
}
