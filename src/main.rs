use std::{net::TcpStream, pin::Pin};

use http_server_starter_rust::{HttpMethod, HttpRequest, HttpResponse, HttpStatus, Result};
use tokio::{io::AsyncRead, net::TcpListener};

async fn try_handle_request(request: HttpRequest) -> Result<HttpResponse> {
    let request = request.parse()?;
    let response = if request.method() == HttpMethod::GET && request.path() == "/" {
        HttpResponse::new(HttpStatus::Ok)
    } else {
        HttpResponse::new(HttpStatus::NotFound)
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    let listen_addr = "127.0.0.1:4221";
    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("Listening on {listen_addr}");
    loop {
        let (mut stream, addr) = listener.accept().await?;
        let mut stream = Pin::new(&mut stream);
        eprintln!("Accepted new connection from {addr}");

        let request = HttpRequest::deserialize(&mut stream).await?;
        let response = try_handle_request(request).await.unwrap_or_else(|err| {
            eprintln!("Error while handling request {err}");
            HttpResponse::new(HttpStatus::InternalServerError)
        });

        response.serialize(&mut stream).await?;
    }
}
