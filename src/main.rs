use tokio::net::TcpListener;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let listen_addr = "127.0.0.1:4221";
    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("Listening on {listen_addr}");
    loop {
        let (_stream, addr) = listener.accept().await?;
        eprintln!("Accepted new connection from {addr}");
    }
}
