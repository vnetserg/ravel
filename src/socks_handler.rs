use std::net::{Ipv4Addr, Ipv6Addr};
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


#[derive(Clone, Debug)]
pub enum NetAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String)
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
        if let Err(err) = conn.write(&reply.to_bytes()) {
            return Err(format!("Failed to write to socket: {}", err));
        }

        eprintln!("Auth negotiation successfull");
        self.state = SocksHandlerState::WaitForRequest;
        return Ok(data);
    }

    fn handle_request_data<'a, 'b, 'c>(&'a mut self,
                                       conn: &'b mut Connection,
                                       data: &'c[u8],
                                       requests: &mut Vec<HandlerRequest>)
        -> Result<&'c [u8], String>
    {
        let (socks, data) = match SocksRequest::parse(data) {
            Some((socks, data)) => (socks, data),
            None => return Err("Invalid socks request, closing".to_string()),
        };

        if socks.version != 5 {
            return Err(format!("Unsupported socks version: {}", socks.version));
        }

        if let SocksCommand::Connect = socks.command {
            requests.push(HandlerRequest::Connect(socks.address.clone(),
                                                  socks.port));
            let reply = SocksReply{version: 5, reply: SocksReplyStatus::Success,
                                   address: socks.address, port: socks.port};
            if let Err(err) = conn.write(&reply.to_bytes()) {
                return Err(format!("Failed to write to socket: {}", err));
            }
            self.state = SocksHandlerState::WaitForRemote;
            return Ok(data);
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


enum SocksCommand {
    Connect,
    Bind,
    Associate
}


struct SocksRequest {
    version: u8,
    command: SocksCommand,
    address: NetAddr,
    port: u16
}

const ATYP_IPV4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_ASSOCIATE: u8 = 0x03;

impl SocksRequest {
    fn parse(data: &[u8]) -> Option<(SocksRequest, &[u8])> {
        let (&version, data) = data.split_first()?;
        let (&command, data) = data.split_first()?;
        let command = match command {
            CMD_CONNECT => SocksCommand::Connect,
            CMD_BIND => SocksCommand::Bind,
            CMD_ASSOCIATE => SocksCommand::Associate,
            _ => return None,
        };

        let (_, data) = data.split_first()?;
        let (&addr_type, data) = data.split_first()?;

        let (address, data) = match addr_type {
            ATYP_IPV4 => {
                if data.len() < 4 {
                    return None;
                }
                (NetAddr::V4(Ipv4Addr::from([
                    data[0], data[1], data[2], data[3]
                ])), &data[4..])
            },
            ATYP_IPV6 => {
                if data.len() < 16 {
                    return None;
                }
                (NetAddr::V6(Ipv6Addr::from([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15],
                ])), &data[16..])
            },
            ATYP_NAME => {
                let (&len, data) = data.split_first()?;
                if data.len() < len as usize {
                    return None;
                }
                let addr = NetAddr::Name(
                    match String::from_utf8(data[.. len as usize].iter().map(|&x| x).collect()) {
                        Ok(s) => s,
                        Err(_) => return None,
                    });
                (addr, &data[len as usize ..])
            },
            _ => return None,
        };

        if data.len() < 2 {
            return None;
        }
        let port = ((data[0] as u16) << 8) + (data[1] as u16);

        Some((SocksRequest{version, command, address, port}, &data[2..]))
    }
}


const REP_SUCCESS: u8 = 0x00;
const REP_FAILURE: u8 = 0x01;

enum SocksReplyStatus {
    Success,
    Failure
}

struct SocksReply {
    version: u8,
    reply: SocksReplyStatus,
    address: NetAddr,
    port: u16
}

impl SocksReply {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.version];
        res.push(match self.reply {
            SocksReplyStatus::Success => REP_SUCCESS,
            SocksReplyStatus::Failure => REP_FAILURE,
        });

        match &self.address {
            &NetAddr::V4(addr) => {
                res.push(ATYP_IPV4);
                for &x in addr.octets().iter() {
                    res.push(x);
                }
            },
            &NetAddr::V6(addr) => {
                res.push(ATYP_IPV6);
                for &x in addr.octets().iter() {
                    res.push(x);
                }
            },
            &NetAddr::Name(ref name) => {
                res.push(ATYP_NAME);
                if name.len() > 255 {
                    panic!("Name is too long");
                }
                res.push(name.len() as u8);
                for &x in name.as_bytes() {
                    res.push(x);
                }
            },
        }

        res.push((self.port >> 8) as u8);
        res.push((self.port & 0xff) as u8);
        
        res
    }
}
