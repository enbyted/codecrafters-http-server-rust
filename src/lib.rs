use itertools::Itertools;
#[warn(missing_debug_implementations)]
use std::pin::Pin;
use std::{borrow::Cow, collections::HashMap, str, string::FromUtf8Error};
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O Error")]
    IoError(#[from] io::Error),
    #[error("Failed to decode utf-8 stream")]
    Utf8Error(#[from] FromUtf8Error),
    #[error("Unknown HTTP method '{0}'")]
    UnknownMethod(String),
    #[error("Invalid status line '{0}'")]
    InvalidStatusLine(String),
    #[error("Unsupported HTTP version '{0}'")]
    UnsupportedHttpVersion(String),
    #[error("Invalid header line: '{0}")]
    InvalidHeaderLine(String),
    #[error("Unexpected end of urlencoded string: '{0}'")]
    UnexpectedEndOfUrlEncodedString(String),
    #[error("Invalid urlencoded sequence '{0}' in '{1}'")]
    InvalidUrlEncodedSequence(String, String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Header {
    ContentLength,
    ContentType,
    UserAgent,
    Custom(String),
}

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
fn urlencode<'a>(value: &'a str) -> Cow<'a, str> {
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

fn urldecode(input: &str) -> Result<Cow<'_, str>> {
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
                match str::from_utf8(&decode_buf) {
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

impl Header {
    fn parse(input: &str) -> Result<(Header, &str)> {
        let (key, value) = input
            .split_once(':')
            .ok_or_else(|| Error::InvalidHeaderLine(input.into()))?;

        let key = key.trim().to_ascii_lowercase();
        let header = match key.as_str() {
            "content-length" => Header::ContentLength,
            "content-type" => Header::ContentType,
            "user-agent" => Header::UserAgent,
            _ => Header::Custom(key),
        };

        Ok((header, value.trim()))
    }

    async fn serialize(&self, value: &str, stream: &mut Pin<&mut impl AsyncWrite>) -> Result<()> {
        let key = match self {
            Header::ContentLength => "Content-Length",
            Header::ContentType => "Content-Type",
            Header::UserAgent => "User-Agent",
            Header::Custom(value) => value.as_str(),
        };

        stream.write_all(key.as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        Ok(())
    }
}

#[repr(u32)]
#[derive(Debug, Clone)]
pub enum HttpStatus {
    Ok = 200,
    BadRequest = 400,
    NotFound = 404,
    InternalServerError = 500,
}

impl HttpStatus {
    async fn serialize(&self, stream: &mut Pin<&mut impl AsyncWrite>) -> io::Result<()> {
        let text = match self {
            HttpStatus::Ok => "OK",
            HttpStatus::BadRequest => "Bad request",
            HttpStatus::NotFound => "Not found",
            HttpStatus::InternalServerError => "Internal server error",
        };

        let code = self.clone() as u32;
        stream
            .write_all(format!("{code} {text}").as_bytes())
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum HttpContent {
    Empty,
    Plain(String),
}

impl HttpContent {
    fn content_type(&self) -> &'static str {
        match self {
            HttpContent::Empty => "text/plain",
            HttpContent::Plain(_) => "text/plain",
        }
    }

    fn len(&self) -> usize {
        match self {
            HttpContent::Empty => 0,
            HttpContent::Plain(text) => text.len(),
        }
    }

    async fn serialize(&self, stream: &mut Pin<&mut impl AsyncWrite>) -> Result<()> {
        match self {
            HttpContent::Empty => {}
            HttpContent::Plain(text) => stream.write_all(text.as_bytes()).await?,
        }

        Ok(())
    }
}

pub struct HttpResponse {
    code: HttpStatus,
    headers: HashMap<Header, String>,
    content: HttpContent,
}

impl HttpResponse {
    pub fn new(code: HttpStatus) -> Self {
        HttpResponse {
            code,
            headers: HashMap::new(),
            content: HttpContent::Empty,
        }
    }

    pub fn set_content(&mut self, content: HttpContent) {
        self.content = content;
    }

    pub async fn serialize(&mut self, stream: &mut Pin<&mut impl AsyncWrite>) -> Result<()> {
        // Content-Length has to match the length of content, so it's replaced
        self.headers
            .insert(Header::ContentLength, self.content.len().to_string());
        // Content-Type is only set if user did not override it
        self.headers
            .entry(Header::ContentType)
            .or_insert_with(|| self.content.content_type().into());

        stream.write_all(b"HTTP/1.1 ").await?;
        self.code.serialize(stream).await?;
        stream.write_all(b"\r\n").await?;
        for (header, value) in self.headers.iter() {
            header.serialize(value, stream).await?;
        }
        stream.write_all(b"\r\n").await?;
        self.content.serialize(stream).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    status_line: String,
    headers: HashMap<Header, String>,
}

impl HttpRequest {
    pub async fn deserialize(stream: &mut Pin<&mut impl AsyncRead>) -> Result<HttpRequest> {
        let status_line = Self::read_line(stream).await?;
        let mut headers: HashMap<Header, String> = HashMap::new();
        loop {
            let header = Self::read_line(stream).await?;
            if header.is_empty() {
                break;
            }
            let (key, value) = Header::parse(&header)?;
            if let Some(existing) = headers.get_mut(&key) {
                existing.reserve(value.len() + 1);
                existing.push(',');
                existing.push_str(value);
            } else {
                headers.insert(key, value.to_owned());
            }
        }

        Ok(HttpRequest {
            status_line,
            headers,
        })
    }

    pub fn parse(&self) -> Result<ParsedHttpRequest<'_>> {
        ParsedHttpRequest::new(self)
    }

    async fn read_line(stream: &mut Pin<&mut impl AsyncRead>) -> Result<String> {
        let mut buffer = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if let Some(last) = buffer.last() {
                if *last == b'\r' && byte == b'\n' {
                    buffer.pop();
                    break;
                }
            }
            buffer.push(byte);
        }

        Ok(String::from_utf8(buffer)?)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
}

impl HttpMethod {
    fn parse(input: &str) -> Result<HttpMethod> {
        match input.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::GET),
            _ => Err(Error::UnknownMethod(input.into())),
        }
    }
}

#[derive(Debug)]
pub struct ParsedHttpRequest<'request> {
    method: HttpMethod,
    path: Vec<Cow<'request, str>>,
    headers: &'request HashMap<Header, String>,
}

impl<'request> ParsedHttpRequest<'request> {
    fn new(input: &'request HttpRequest) -> Result<Self> {
        let (method, path, version) = input
            .status_line
            .split(' ')
            .collect_tuple()
            .ok_or_else(|| Error::InvalidStatusLine(input.status_line.clone()))?;

        let version = version.trim().to_ascii_uppercase();
        if version != "HTTP/1.1" {
            return Err(Error::UnsupportedHttpVersion(version));
        }

        let method = HttpMethod::parse(method)?;
        let path = path
            .split('/')
            .filter_map(|segment| {
                let segment = segment.trim();
                if segment.is_empty() {
                    None
                } else {
                    Some(urldecode(segment))
                }
            })
            .collect::<Result<_>>()?;
        Ok(ParsedHttpRequest {
            method,
            path,
            headers: &input.headers,
        })
    }

    pub fn method(&self) -> HttpMethod {
        self.method.clone()
    }

    pub fn path(&self) -> impl Iterator<Item = &str> {
        self.path.iter().map(|s| s.as_ref())
    }

    pub fn header(&self, header: Header) -> Option<&String> {
        self.headers.get(&header)
    }
}
