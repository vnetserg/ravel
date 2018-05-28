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
    Closed
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
    {
        while data.len() > 0 {
            data = match self.state {
                SocksHandlerState::WaitForAuth =>
                    self.handle_auth_data(conn, data),
                SocksHandlerState::WaitForRequest => {
                    conn.write(data).unwrap_or_else(|err| {
                        eprintln!("Failed to write to socket: {}", err);
                        0
                    });
                    &[]
                }
                SocksHandlerState::Closed => break,
            }
        }
    }

    fn handle_auth_data<'a, 'b, 'c>(&'a mut self, conn: &'b mut Connection,
                                    data: &'c[u8]) -> &'c[u8]
    {
        let (request, data) = match AuthRequest::parse(data) {
            Some((request, data)) => (request, data),
            None => {
                eprintln!("Invalid AuthRequest, closing connection");
                self.close();
                return &[];
            }
        };

        if request.version != 5 {
            eprintln!("Unsupported socks version: {}", request.version);
            self.close();
            return &[];
        }

        if !request.methods.contains(&AuthMethod::Unauthorized) {
            eprintln!("No supported auth method");
            self.close();
            return &[];
        }

        let reply = AuthReply{version: 5, method: AuthMethod::Unauthorized};
        conn.write(&reply.to_bytes()).unwrap_or_else(|err| {
            eprintln!("Failed to write to socket: {}", err);
            0
        });

        eprintln!("Auth negotiation successfull");
        self.state = SocksHandlerState::WaitForRequest;
        return data;
    }

    pub fn close(&mut self) {
        self.state = SocksHandlerState::Closed;
    }

    pub fn state(&self) -> &SocksHandlerState {
        &self.state
    }

    pub fn is_closed(&self) -> bool {
        match self.state {
            SocksHandlerState::Closed => true,
            _ => false
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
            AuthMethod::Unauthorized => 0,
            AuthMethod::Other => panic!("Can not convert AuthMethod::Other \
                                         to bytes!")
        };
        [self.version, method]
    }
}
