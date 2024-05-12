use std::borrow::Cow;
use crate::error::{Result, Error};

#[allow(dead_code)]
fn to_hex(val: u8) -> [char; 2] {
    fn digit(d: u8) -> char {
        if d <= 9 {
            char::from_u32((d as u32) + (b'0' as u32)).expect("0-9 are valid ascii chars")
        } else if d <= 15 {
            char::from_u32((d as u32) - 10u32 + (b'A' as u32)).expect("A-F are valid ascii chars")
        } else {
            unreachable!()
        }
    }

    [digit((val >> 4) & 0x0F), digit(val & 0x0F)]
}

#[allow(dead_code)]
pub fn urlencode<'a>(value: &'a str) -> Cow<'a, str> {
    let mut encoded = String::with_capacity(value.len());
    let mut changed = false;
    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            encoded.push(c)
        } else if ['.', ' ', '-', '_'].contains(&c) {
            encoded.push(c)
        } else {
            changed = true;
            let mut buf = [0; 4];
            let len = c.encode_utf8(&mut buf).len();

            encoded.reserve(len * 3);
            for b in &buf[..len] {
                let chars = to_hex(*b);
                encoded.push('%');
                encoded.push(chars[0]);
                encoded.push(chars[1]);
            }
        }
    }

    if changed {
        Cow::Owned(encoded)
    } else {
        Cow::Borrowed(value)
    }
}

pub fn urldecode(input: &str) -> Result<Cow<'_, str>> {
    let mut decoded = String::with_capacity(input.len());
    let mut decode_buf = Vec::new();
    let mut changed = false;
    let mut chars = input.chars();

    fn from_hex_digit(digit: char) -> Option<u8> {
        match digit {
            '0'..='9' => Some(digit as u8 - b'0'),
            'A'..='F' => Some(digit as u8 - b'A' + 10),
            'a'..='f' => Some(digit as u8 - b'a' + 10),
            _ => None,
        }
    }

    fn read_hex(iter: &mut impl Iterator<Item = char>, whole_string: &str) -> Result<u8> {
        let msb = iter
            .next()
            .ok_or_else(|| Error::UnexpectedEndOfUrlEncodedString(whole_string.into()))?;
        let lsb = iter
            .next()
            .ok_or_else(|| Error::UnexpectedEndOfUrlEncodedString(whole_string.into()))?;

        let msb = from_hex_digit(msb).ok_or_else(|| {
            Error::InvalidUrlEncodedSequence(format!("{msb}{lsb}"), whole_string.into())
        })?;
        let lsb = from_hex_digit(lsb).ok_or_else(|| {
            Error::InvalidUrlEncodedSequence(format!("{msb}{lsb}"), whole_string.into())
        })?;

        Ok((msb << 4) | lsb)
    }

    while let Some(ch) = chars.next() {
        if ch == '%' {
            decode_buf.clear();
            decode_buf.push(read_hex(&mut chars, input)?);
            loop {
                match std::str::from_utf8(&decode_buf) {
                    Ok(str) => {
                        decoded.push_str(str);
                        changed = true;
                        break;
                    }
                    Err(_) => {
                        let ch = chars
                            .next()
                            .ok_or_else(|| Error::UnexpectedEndOfUrlEncodedString(input.into()))?;
                        if ch != '%' {
                            return Err(Error::InvalidUrlEncodedSequence(
                                format!("{ch}"),
                                input.into(),
                            ));
                        }
                        decode_buf.push(read_hex(&mut chars, input)?);
                    }
                }
            }
        } else if ch == '+' {
            decoded.push(' ');
            changed = true;
        } else {
            decoded.push(ch);
        }
    }

    if changed {
        Ok(Cow::Owned(decoded))
    } else {
        Ok(Cow::Borrowed(input))
    }
}

pub fn urldecode_bytes(input: &str) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut chars = input.chars();

    fn from_hex_digit(digit: char) -> Option<u8> {
        match digit {
            '0'..='9' => Some(digit as u8 - b'0'),
            'A'..='F' => Some(digit as u8 - b'A' + 10),
            'a'..='f' => Some(digit as u8 - b'a' + 10),
            _ => None,
        }
    }

    fn read_hex(iter: &mut impl Iterator<Item = char>, whole_string: &str) -> Result<u8> {
        let msb = iter
            .next()
            .ok_or_else(|| Error::UnexpectedEndOfUrlEncodedString(whole_string.into()))?;
        let lsb = iter
            .next()
            .ok_or_else(|| Error::UnexpectedEndOfUrlEncodedString(whole_string.into()))?;

        let msb = from_hex_digit(msb).ok_or_else(|| {
            Error::InvalidUrlEncodedSequence(format!("{msb}{lsb}"), whole_string.into())
        })?;
        let lsb = from_hex_digit(lsb).ok_or_else(|| {
            Error::InvalidUrlEncodedSequence(format!("{msb}{lsb}"), whole_string.into())
        })?;

        Ok((msb << 4) | lsb)
    }

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let value = read_hex(&mut chars, input)?;
            decoded.push(value);
        } else if ch == '+' {
            decoded.push(b' ');
        } else if ch.is_ascii() {
            decoded.push(ch as u8);
        } else {
            return Err(Error::InvalidUrlEncodedSequence(
                format!("{ch}"),
                input.into(),
            ));
        }
    }

    Ok(decoded)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encoding_test() {
        assert_eq!(urlencode("1234567890!@#$%^&*()"), "1234567890%21%40%23%24%25%5E%26%2A%28%29");
    }

    #[test]
    fn decoding_test() {
        assert_eq!(urldecode("1234567890%21%40%23%24%25%5E%26%2A%28%29"), Ok(Cow::Borrowed("1234567890!@#$%^&*()")));
        assert_eq!(urldecode_bytes("1234567890%21%40%23%24%25%5E%26%2A%28%29"), Ok(Vec::from(b"1234567890!@#$%^&*()")))
    }
}