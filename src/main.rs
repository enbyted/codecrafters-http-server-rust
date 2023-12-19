use std::{collections::HashMap, path::PathBuf, pin::Pin};

use http_server_starter_rust::{
    Error, Header, HttpContent, HttpMethod, HttpRequest, HttpResponse, HttpStatus,
    ParsedHttpRequest, Result,
};
use itertools::Itertools;
use std::net::SocketAddr;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum MatchSegment {
    Const(&'static str),
    Var,
    All,
}

impl MatchSegment {
    fn matches(&self, value: Option<&str>) -> bool {
        match self {
            Self::All | Self::Var => value.is_some(),
            Self::Const(v) => value.map(|value| value == *v).unwrap_or(false),
        }
    }

    fn accepts_everything(&self) -> bool {
        match self {
            Self::All => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RouteInfo {
    method: HttpMethod,
    path: Vec<MatchSegment>,
}

impl RouteInfo {
    fn new(method: HttpMethod, pattern: &'static str) -> Self {
        let path = pattern
            .split('/')
            .filter_map(|segment| {
                if segment.is_empty() {
                    None
                } else if segment.starts_with(':') {
                    Some(MatchSegment::Var)
                } else if segment.starts_with('*') {
                    Some(MatchSegment::All)
                } else {
                    Some(MatchSegment::Const(segment))
                }
            })
            .collect();

        Self { method, path }
    }

    fn matches(&self, request: &ParsedHttpRequest<'_>) -> bool {
        self.method == request.method() && self.match_path(request.path())
    }

    fn match_path<'a>(&self, mut path: impl Iterator<Item = &'a str>) -> bool {
        let mut was_none = false;
        let mut allows_overflow = false;
        for segment in &self.path {
            let v = if was_none { None } else { path.next() };
            was_none = v.is_none();
            if !segment.matches(v) {
                return false;
            }
            allows_overflow = segment.accepts_everything();
            if allows_overflow {
                break;
            }
        }

        return allows_overflow || was_none || path.next().is_none();
    }
}

trait Route {
    fn execute<'data>(&mut self, request: &ParsedHttpRequest<'data>) -> Result<HttpResponse>;
}

impl std::fmt::Debug for dyn Route + Send {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[Route]")
    }
}

impl<T: FnMut(&ParsedHttpRequest<'_>) -> Result<HttpResponse>> Route for T {
    fn execute(&mut self, request: &ParsedHttpRequest<'_>) -> Result<HttpResponse> {
        self(request)
    }
}

#[derive(Debug)]
struct Router {
    routes: HashMap<RouteInfo, Box<dyn Route + Send>>,
}

impl Router {
    fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    fn add_route<T>(&mut self, route: RouteInfo, handler: T)
    where
        T: Route + Send + 'static,
    {
        self.routes.insert(route, Box::new(handler));
    }
}

impl Route for Router {
    fn execute(&mut self, request: &ParsedHttpRequest<'_>) -> Result<HttpResponse> {
        let route = self
            .routes
            .iter_mut()
            .find(|(route, _)| route.matches(request));

        if let Some((_, route)) = route {
            route.execute(request)
        } else {
            Ok(HttpResponse::new(HttpStatus::NotFound))
        }
    }
}

fn handle_root(_req: &ParsedHttpRequest<'_>) -> Result<HttpResponse> {
    Ok(HttpResponse::new(HttpStatus::Ok))
}

fn handle_echo(req: &ParsedHttpRequest<'_>) -> Result<HttpResponse> {
    let mut resp = HttpResponse::new(HttpStatus::Ok);
    resp.set_content(HttpContent::Plain(req.path().skip(1).join("/")));
    Ok(resp)
}

fn handle_user_agent(req: &ParsedHttpRequest<'_>) -> Result<HttpResponse> {
    if let Some(user_agent) = req.header(Header::UserAgent) {
        let mut resp = HttpResponse::new(HttpStatus::Ok);
        resp.set_content(HttpContent::Plain(user_agent.clone()));
        Ok(resp)
    } else {
        Ok(HttpResponse::new(HttpStatus::BadRequest))
    }
}

async fn handle_request_result(
    stream: &mut Pin<&mut TcpStream>,
    addr: SocketAddr,
    router: &Mutex<Router>,
) -> Result<HttpResponse> {
    eprintln!("Accepted new connection from {addr}");

    let request = HttpRequest::deserialize(stream).await?;
    let request = request.parse()?;
    eprintln!("Handling request {request:?}");
    router.lock().await.execute(&request)
}

async fn handle_request(mut stream: TcpStream, addr: SocketAddr, router: &Mutex<Router>) {
    let mut stream = Pin::new(&mut stream);
    let mut response = handle_request_result(&mut stream, addr, router)
        .await
        .unwrap_or_else(|err| {
            eprintln!("Error while handling request {err}");
            HttpResponse::new(HttpStatus::InternalServerError)
        });
    response
        .serialize(&mut stream)
        .await
        .unwrap_or_else(|e| eprintln!("Error while sending response {e}"));
}

struct FileResolver(PathBuf);

impl Route for FileResolver {
    fn execute<'data>(&mut self, request: &ParsedHttpRequest<'data>) -> Result<HttpResponse> {
        let file_path = request.path().skip(1).join("/");
        let file_path = self.0.join(file_path);
        eprintln!("Trying to read file {file_path:?}");
        match std::fs::read(file_path) {
            Ok(data) => {
                let mut response = HttpResponse::new(HttpStatus::Ok);
                response.set_content(HttpContent::OctedStream(data));
                Ok(response)
            }
            Err(err) => {
                eprintln!("Failed: {err}");
                if err.kind() == std::io::ErrorKind::NotFound {
                    Ok(HttpResponse::new(HttpStatus::NotFound))
                } else {
                    Err(err.into())
                }
            }
        }
    }
}

struct FilePoster(PathBuf);

impl Route for FilePoster {
    fn execute<'data>(&mut self, request: &ParsedHttpRequest<'data>) -> Result<HttpResponse> {
        let file_path = request.path().skip(1).join("/");
        let file_path = self.0.join(file_path);

        let content = match request.header(Header::ContentType).map(|s| s.as_str()) {
            Some("application/x-www-form-urlencoded") => request.content_urldecoded().ok(),
            _ => None,
        };
        if let Some(content) = content {
            eprintln!("Trying to write file {file_path:?}");
            Ok(std::fs::write(file_path, &content)
                .map(|_| HttpResponse::new(HttpStatus::Created))?)
        } else {
            eprintln!("Failed to read data from request");
            Ok(HttpResponse::new(HttpStatus::BadRequest))
        }
    }
}

fn print_usage(prog: &str) {
    println!("Usage: {prog} [--directory <serve root>]");
}

#[tokio::main]
async fn main() -> Result<()> {
    let router = Box::leak(Box::new(Mutex::new(Router::new())));

    {
        let router = router.get_mut();
        router.add_route(RouteInfo::new(HttpMethod::GET, "/"), handle_root);
        router.add_route(RouteInfo::new(HttpMethod::GET, "/echo/*"), handle_echo);
        router.add_route(
            RouteInfo::new(HttpMethod::GET, "/user-agent"),
            handle_user_agent,
        );

        let args = std::env::args().collect_vec();
        if args.len() == 3 {
            if args[1] == "--directory" {
                eprintln!("Adding directory route for {}", args[2]);
                router.add_route(
                    RouteInfo::new(HttpMethod::GET, "/files/*"),
                    FileResolver(args[2].clone().into()),
                );
                router.add_route(
                    RouteInfo::new(HttpMethod::POST, "/files/*"),
                    FilePoster(args[2].clone().into()),
                );
            } else {
                print_usage(&args[0]);
                return Ok(());
            }
        } else if args.len() == 1 {
            // Nothing
        } else {
            print_usage(&args[0]);
            return Ok(());
        }
    }
    let listen_addr = "127.0.0.1:4221";
    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("Listening on {listen_addr}");
    eprintln!("Routes: {router:?}");
    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(handle_request(stream, addr, router));
    }
}
