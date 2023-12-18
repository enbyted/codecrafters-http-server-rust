use itertools::Itertools;
#[warn(missing_debug_implementations)]
use std::pin::Pin;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O Error")]
    IoError(#[from] io::Error),
    #[error("Unknown HTTP method '{0}'")]
    UnknownMethod(String),
    #[error("Invalid status line '{0}'")]
    InvalidStatusLine(String),
    #[error("Unsupported HTTP version '{0}'")]
    UnsupportedHttpVersion(String),
}

pub type Result<T> = std::result::Result<T, Error>;

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

pub struct HttpResponse {
    code: HttpStatus,
}

impl HttpResponse {
    pub fn new(code: HttpStatus) -> Self {
        HttpResponse { code }
    }

    pub async fn serialize(&self, stream: &mut Pin<&mut impl AsyncWrite>) -> io::Result<()> {
        stream.write_all(b"HTTP/1.1 ").await?;
        self.code.serialize(stream).await?;
        stream.write_all(b"\r\n").await?;
        // TODO: headers
        stream.write_all(b"\r\n").await?;
        // TODO: content
        Ok(())
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    status_line: String,
    headers: Vec<String>,
}

impl HttpRequest {
    pub async fn deserialize(stream: &mut Pin<&mut impl AsyncRead>) -> Result<HttpRequest> {
        let status_line = Self::read_line(stream).await?;
        let mut headers = Vec::new();
        loop {
            let header = Self::read_line(stream).await?;
            if header.is_empty() {
                break;
            }
            headers.push(header);
        }

        Ok(HttpRequest {
            status_line,
            headers,
        })
    }

    pub fn parse(&self) -> Result<ParsedHttpRequest<'_>> {
        ParsedHttpRequest::new(self)
    }

    async fn read_line(stream: &mut Pin<&mut impl AsyncRead>) -> io::Result<String> {
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

        String::from_utf8(buffer).map_err(|err| io::Error::other(err))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    path: &'request str,
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

        Ok(ParsedHttpRequest { method, path })
    }

    pub fn method(&self) -> HttpMethod {
        self.method.clone()
    }

    pub fn path(&self) -> &str {
        self.path
    }
}
