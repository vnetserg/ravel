use std::ops::Drop;
use std::io::{Write, Read};

use conn::Connection;
use socks::data::*;


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
    Connect(NetAddr, u16),
    Close
}


pub struct SocksHandler {
    state: SocksHandlerState,
}

impl SocksHandler {
    pub fn new(conn: &Connection) -> SocksHandler {
        eprintln!("Created handler for {}", conn.addr());
        SocksHandler{ state: SocksHandlerState::WaitForAuth }
    }

    pub fn handle_connection_data<'a, 'b>(&'a mut self,
                                          conn: &'b mut Connection,
                                          mut data: &[u8])
        -> Vec<HandlerRequest>
    {
        let mut requests = Vec::new();

        while !data.is_empty() {
            let result = match self.state {
                SocksHandlerState::WaitForAuth =>
                    self.handle_auth_data(conn, &mut data),
                SocksHandlerState::WaitForRequest =>
                    self.handle_request_data(conn, &mut data, &mut requests),
                SocksHandlerState::WaitForRemote => Ok(()),
                SocksHandlerState::Closed => break,
            };

            if let Err(err) = result {
                eprintln!("Handler error: {}", err);
                self.state = SocksHandlerState::Closed;
                requests.push(HandlerRequest::Close);
                break;
            }
        }

        requests
    }

    fn handle_auth_data<'a, 'b, T: Read>(&'a mut self,
                                         conn: &'b mut Connection,
                                         data: T)
        -> Result<(), String>
    {
        let request = match AuthRequest::parse(data) {
            Some(request) => request,
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
        if let Err(err) = conn.write(&reply.to_bytes()) {
            return Err(format!("Failed to write to socket: {}", err));
        }

        eprintln!("Auth negotiation successfull");
        self.state = SocksHandlerState::WaitForRequest;
        return Ok(());
    }

    fn handle_request_data<'a, 'b, T: Read>(&'a mut self,
                                            conn: &'b mut Connection,
                                            data: T,
                                            requests: &mut Vec<HandlerRequest>)
        -> Result<(), String>
    {
        let socks = match SocksRequest::parse(data) {
            Some(socks) => socks,
            None => return Err("Invalid socks request, closing".to_string()),
        };

        if socks.version != 5 {
            return Err(format!("Unsupported socks version: {}", socks.version));
        }

        if let SocksCommand::Connect = socks.command {
            requests.push(HandlerRequest::Connect(socks.address.clone(),
                                                  socks.port));
            let reply = SocksReply {
                version: 5,
                status: SocksReplyStatus::Success,
                address: socks.address,
                port: socks.port
            };
            if let Err(err) = conn.write(&reply.to_bytes()) {
                return Err(format!("Failed to write to socket: {}", err));
            }
            self.state = SocksHandlerState::WaitForRemote;
            return Ok(());
        } else {
            return Err(format!("Unsupported socks command"));
        }
    }
}

impl Drop for SocksHandler {
    fn drop(&mut self) {
        eprintln!("Dropped handler");
    }
}
