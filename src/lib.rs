#[warn(missing_debug_implementations)]
use std::pin::Pin;
use tokio::io::{AsyncWrite, AsyncWriteExt, self};

#[repr(u32)]
#[derive(Debug, Clone)]
pub enum HttpStatus {
    Ok = 200,
}

impl HttpStatus {
    async fn serialize(&self, mut stream: Pin<&mut dyn AsyncWrite>) -> io::Result<()>
    {
        let text = match self {
            HttpStatus::Ok => "OK"
        };

        let code = self.clone() as u32;
        stream.write_all(format!("{code} {text}").as_bytes()).await?;
        Ok(())
    }
}

pub struct HttpResponse {
    code: HttpStatus,
}

impl HttpResponse {
    pub fn new(code: HttpStatus) -> Self {
        HttpResponse {
            code
        }
    }

    pub async fn serialize(&self, mut stream: Pin<&mut dyn AsyncWrite>) -> io::Result<()> {
        stream.write_all(b"HTTP/1.1 ").await?;
        self.code.serialize(stream.as_mut()).await?;
        stream.write_all(b"\r\n").await?;
        // TODO: headers
        stream.write_all(b"\r\n").await?;
        // TODO: content
        Ok(())
    }
}