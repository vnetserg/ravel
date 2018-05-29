use std::net::SocketAddr;
use std::ops::Drop;
use std::io::Write;

use conn::Connection;


pub struct SocksHandlerFactory {

}

impl SocksHandlerFactory {
    pub fn new() -> SocksHandlerFactory {
        SocksHandlerFactory{}
    }

    pub fn new_handler(&self, conn: &Connection) -> SocksHandler {
        SocksHandler::new(conn)
    }
}


pub enum SocksHandlerState {
    WaitForAuth,
    WaitForRequest,
    WaitForRemote,
    Closed
}


pub enum HandlerRequest {
    Connect(SocketAddr),
    Close
}


pub struct SocksHandler {
    state: SocksHandlerState,
}

impl SocksHandler {
    pub fn new(conn: &Connection) -> SocksHandler {
        eprintln!("Created handler for {:?}", conn.addr());
        SocksHandler{ state: SocksHandlerState::WaitForAuth }
    }

    pub fn handle_connection_data<'a, 'b, 'c>(&'a mut self,
                                              conn: &'b mut Connection,
                                              mut data: &'c [u8])
        -> Vec<HandlerRequest>
    {
        let mut requests = Vec::new();

        while data.len() > 0 {
            let data_or_err = match self.state {
                SocksHandlerState::WaitForAuth =>
                    self.handle_auth_data(conn, data),
                SocksHandlerState::WaitForRequest =>
                    self.handle_request_data(conn, data, &mut requests),
                SocksHandlerState::WaitForRemote => match conn.write(data) {
                    Ok(_) => break,
                    Err(err) => Err(err.to_string()),
                },
                SocksHandlerState::Closed => break,
            };

            data = match data_or_err {
                Ok(data) => data,
                Err(err) => {
                    eprintln!("Handler error: {}", err);
                    self.state = SocksHandlerState::Closed;
                    requests.push(HandlerRequest::Close);
                    break;
                }
            };
        }

        requests
    }

    fn handle_auth_data<'a, 'b, 'c>(&'a mut self, conn: &'b mut Connection,
                                    data: &'c[u8]) -> Result<&'c [u8], String>
    {
        let (request, data) = match AuthRequest::parse(data) {
            Some((request, data)) => (request, data),
            None => {
                return Err("Invalid AuthRequest, closing connection"
                           .to_string());
            }
        };

        if request.version != 5 {
            return Err(format!("Unsupported socks version: {}",
                               request.version));
        }

        if !request.methods.contains(&AuthMethod::Unauthorized) {
            let reply = AuthReply{version: 5, method: AuthMethod::NoMethod};
            let _ = conn.write(&reply.to_bytes());
            return Err("No supported auth method".to_string());
        }

        let reply = AuthReply{version: 5, method: AuthMethod::Unauthorized};
        match conn.write(&reply.to_bytes()) {
            Ok(_) => (),
            Err(err) => return Err(format!("Failed to write to socket: {}",
                                           err))
        }

        eprintln!("Auth negotiation successfull");
        self.state = SocksHandlerState::WaitForRequest;
        return Ok(data);
    }

    fn handle_request_data<'a, 'b, 'c>(&'a mut self,
                                       conn: &'b mut Connection,
                                       data: &'c[u8],
                                       _requests: &mut Vec<HandlerRequest>)
        -> Result<&'c [u8], String>
    {
        match conn.write(data) {
            Ok(_) => Ok(&[]),
            Err(err) => Err(err.to_string())
        }
    }
}

impl Drop for SocksHandler {
    fn drop(&mut self) {
        eprintln!("Dropped handler");
    }
}


#[derive(PartialEq)]
enum AuthMethod {
    Unauthorized,
    NoMethod,
    Other
}

struct AuthRequest {
    version: u8,
    methods: Vec<AuthMethod>
}

impl AuthRequest {
    pub fn parse(data: &[u8]) -> Option<(AuthRequest, &[u8])> {
        let (&version, data) = data.split_first()?;
        let (&n_methods, data) = data.split_first()?;

        if data.len() < n_methods as usize {
            return None;
        }

        let methods = data[.. n_methods as usize].iter().map(|&x|
            match x {
                0 => AuthMethod::Unauthorized,
                _ => AuthMethod::Other
            }
        ).collect();

        Some((AuthRequest{ version, methods }, &data[n_methods as usize ..]))
    }
}


struct AuthReply {
    version: u8,
    method: AuthMethod
}

impl AuthReply {
    fn to_bytes(&self) -> [u8; 2] {
        let method = match self.method {
            AuthMethod::Unauthorized => 0x00,
            AuthMethod::NoMethod => 0xff,
            AuthMethod::Other => panic!("Can not convert AuthMethod::Other \
                                         to bytes!")
        };
        [self.version, method]
    }
}
