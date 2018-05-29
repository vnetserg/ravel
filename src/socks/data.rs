use std::net::{Ipv4Addr, Ipv6Addr};


#[derive(Clone, Debug)]
pub enum NetAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String)
}


#[derive(PartialEq)]
pub enum AuthMethod {
    Unauthorized,
    NoMethod,
    Other
}

pub struct AuthRequest {
    pub version: u8,
    pub methods: Vec<AuthMethod>
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


pub struct AuthReply {
    pub version: u8,
    pub method: AuthMethod
}

impl AuthReply {
    pub fn to_bytes(&self) -> [u8; 2] {
        let method = match self.method {
            AuthMethod::Unauthorized => 0x00,
            AuthMethod::NoMethod => 0xff,
            AuthMethod::Other => panic!("Can not convert AuthMethod::Other \
                                         to bytes!")
        };
        [self.version, method]
    }
}


pub enum SocksCommand {
    Connect,
    Bind,
    Associate
}


pub struct SocksRequest {
    pub version: u8,
    pub command: SocksCommand,
    pub address: NetAddr,
    pub port: u16
}

const ATYP_IPV4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_ASSOCIATE: u8 = 0x03;

impl SocksRequest {
    pub fn parse(data: &[u8]) -> Option<(SocksRequest, &[u8])> {
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

pub enum SocksReplyStatus {
    Success,
    Failure
}

pub struct SocksReply {
    pub version: u8,
    pub reply: SocksReplyStatus,
    pub address: NetAddr,
    pub port: u16
}

impl SocksReply {
    pub fn to_bytes(&self) -> Vec<u8> {
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
