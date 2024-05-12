use itertools::Itertools;
#[warn(missing_debug_implementations)]
use std::pin::Pin;
use std::{borrow::Cow, collections::HashMap, str};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod error;
pub use error::{Error, Result};

mod urlencoding;
use urlencoding::{urldecode, urldecode_bytes};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Header {
    ContentLength,
    ContentType,
    UserAgent,
    AcceptEncoding,
    ContentEncoding,
    Custom(String),
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
            "accept-encoding" => Header::AcceptEncoding,
            "content-encoding" => Header::ContentEncoding,
            _ => Header::Custom(key),
        };

        Ok((header, value.trim()))
    }

    async fn serialize(&self, value: &str, stream: &mut Pin<&mut impl AsyncWrite>) -> Result<()> {
        let key = match self {
            Header::ContentLength => "Content-Length",
            Header::ContentType => "Content-Type",
            Header::UserAgent => "User-Agent",
            Header::AcceptEncoding => "Accept-Encoding",
            Header::ContentEncoding => "Content-Encoding",
            Header::Custom(value) => value.as_str(),
        };

        stream.write_all(key.as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AcceptedEncoding<'a> {
    Gzip,
    Unknown(&'a str),
}

impl<'a> AcceptedEncoding<'a> {
    fn parse(input: &'a str) -> Self {
        let value = input.trim();
        if value.eq_ignore_ascii_case("gzip") {
            AcceptedEncoding::Gzip
        } else {
            AcceptedEncoding::Unknown(value)
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone)]
pub enum HttpStatus {
    Ok = 200,
    Created = 201,
    BadRequest = 400,
    NotFound = 404,
    InternalServerError = 500,
}

impl HttpStatus {
    async fn serialize(&self, stream: &mut Pin<&mut impl AsyncWrite>) -> io::Result<()> {
        let text = match self {
            HttpStatus::Ok => "OK",
            HttpStatus::Created => "Created",
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
    OctedStream(Vec<u8>),
}

impl HttpContent {
    fn content_type(&self) -> &'static str {
        match self {
            HttpContent::Empty => "text/plain",
            HttpContent::Plain(_) => "text/plain",
            HttpContent::OctedStream(_) => "application/octet-stream",
        }
    }

    fn len(&self) -> usize {
        match self {
            HttpContent::Empty => 0,
            HttpContent::Plain(text) => text.len(),
            HttpContent::OctedStream(data) => data.len(),
        }
    }

    async fn serialize(&self, stream: &mut Pin<&mut impl AsyncWrite>) -> Result<()> {
        match self {
            HttpContent::Empty => {}
            HttpContent::Plain(text) => stream.write_all(text.as_bytes()).await?,
            HttpContent::OctedStream(data) => stream.write_all(&data).await?,
        }

        Ok(())
    }
}

pub enum ResponseEncoding {
    Normal,
    Gzip { encoded_data: Vec<u8> },
}

impl ResponseEncoding {
    async fn encode(&mut self) -> Result<()> {
        // do nothing for now
        Ok(())
    }

    fn update_headers(&self, content: &HttpContent, headers: &mut HashMap<Header, String>) {
        match self {
            ResponseEncoding::Normal => {
                headers.insert(Header::ContentLength, content.len().to_string());
            }
            ResponseEncoding::Gzip { .. } => {
                headers.insert(Header::ContentLength, content.len().to_string());
                headers.insert(Header::ContentEncoding, String::from("gzip"));
            }
        }
    }

    async fn serialize_content(
        &self,
        content: &HttpContent,
        stream: &mut Pin<&mut impl AsyncWrite>,
    ) -> Result<()> {
        content.serialize(stream).await
    }
}

pub struct HttpResponse {
    code: HttpStatus,
    headers: HashMap<Header, String>,
    content: HttpContent,
    encoding: ResponseEncoding,
}

impl HttpResponse {
    pub fn new(code: HttpStatus) -> Self {
        HttpResponse {
            code,
            headers: HashMap::new(),
            content: HttpContent::Empty,
            encoding: ResponseEncoding::Normal,
        }
    }

    pub fn encode_gzip(&mut self) {
        self.encoding = ResponseEncoding::Gzip {
            encoded_data: Vec::new(),
        };
    }

    pub fn set_content(&mut self, content: HttpContent) {
        self.content = content;
    }

    pub async fn serialize(&mut self, stream: &mut Pin<&mut impl AsyncWrite>) -> Result<()> {
        // Content-Type is only set if user did not override it
        self.headers
            .entry(Header::ContentType)
            .or_insert_with(|| self.content.content_type().into());

        self.encoding.encode().await?;
        self.encoding
            .update_headers(&self.content, &mut self.headers);

        stream.write_all(b"HTTP/1.1 ").await?;
        self.code.serialize(stream).await?;
        stream.write_all(b"\r\n").await?;
        for (header, value) in self.headers.iter() {
            header.serialize(value, stream).await?;
        }
        stream.write_all(b"\r\n").await?;
        self.encoding
            .serialize_content(&self.content, stream)
            .await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    status_line: String,
    headers: HashMap<Header, String>,
    content: Vec<u8>,
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

        let content = if let Some(content_length) = headers
            .get(&Header::ContentLength)
            .and_then(|v| v.parse::<usize>().ok())
        {
            let mut buf = Vec::with_capacity(content_length);
            buf.resize(content_length, 0);
            stream.read_exact(&mut buf).await?;
            buf
        } else {
            Vec::new()
        };

        Ok(HttpRequest {
            status_line,
            headers,
            content,
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
    POST,
}

impl HttpMethod {
    fn parse(input: &str) -> Result<HttpMethod> {
        match input.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::GET),
            "POST" => Ok(HttpMethod::POST),
            _ => Err(Error::UnknownMethod(input.into())),
        }
    }
}

#[derive(Debug)]
pub struct ParsedHttpRequest<'request> {
    method: HttpMethod,
    path: Vec<Cow<'request, str>>,
    headers: &'request HashMap<Header, String>,
    content: &'request [u8],
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
            content: &input.content,
        })
    }

    pub fn accepted_encodings(&self) -> Vec<AcceptedEncoding<'request>> {
        let mut ret = Vec::new();

        if let Some(value) = self.headers.get(&Header::AcceptEncoding) {
            for item in value.split(',') {
                ret.push(AcceptedEncoding::parse(item));
            }
        }

        ret
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

    pub fn content_urldecoded(&self) -> Result<Vec<u8>> {
        urldecode_bytes(str::from_utf8(self.content)?)
    }

    pub fn content(&self) -> &[u8] {
        self.content
    }
}
