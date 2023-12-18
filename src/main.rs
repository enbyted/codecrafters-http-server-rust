use std::pin::Pin;

use http_server_starter_rust::{HttpResponse, HttpStatus};
use tokio::net::TcpListener;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let listen_addr = "127.0.0.1:4221";
    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("Listening on {listen_addr}");
    loop {
        let (mut stream, addr) = listener.accept().await?;
        let stream = Pin::new(&mut stream);
        eprintln!("Accepted new connection from {addr}");
        
        let response = HttpResponse::new(HttpStatus::Ok);
        response.serialize(stream).await?;
    }
}
