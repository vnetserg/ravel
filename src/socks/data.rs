use num;

use std::io::Read;
use std::convert::From;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{NetworkEndian, ReadBytesExt};


macro_rules! get {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(_) => return None,
    });
}


#[derive(Clone, Debug)]
pub enum NetAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String)
}


#[derive(Clone, Copy, PartialEq, FromPrimitive)]
pub enum AuthMethod {
    Unauthorized = 0x00,
    GssApi = 0x01,
    UserPass = 0x02,
    Other,
    NoMethod = 0xff,
}

impl From<u8> for AuthMethod {
    fn from(x: u8) -> AuthMethod {
        match num::FromPrimitive::from_u8(x) {
            Some(method) => method,
            None => AuthMethod::Other,
        }
    }
}


pub struct AuthRequest {
    pub version: u8,
    pub methods: Vec<AuthMethod>
}

impl AuthRequest {
    pub fn parse<T: Read>(mut data: T) -> Option<AuthRequest> {
        let version = get!(data.read_u8());
        let n_methods = get!(data.read_u8());
        let methods: Vec<Option<AuthMethod>> = (0..n_methods).map(|_|
            Some(AuthMethod::from(get!(data.read_u8())))
        ).collect();

        if methods.contains(&None) {
            return None;
        }
        let methods = methods.into_iter().map(|x| x.unwrap()).collect();

        Some(AuthRequest{ version, methods })
    }
}


pub struct AuthReply {
    pub version: u8,
    pub method: AuthMethod
}

impl AuthReply {
    pub fn to_bytes(&self) -> [u8; 2] {
        if let AuthMethod::Other = self.method {
            panic!("Can not convert AuthMethod::Other to bytes!")
        }
        [self.version, self.method as u8]
    }
}

#[derive(Clone, Copy, FromPrimitive)]
pub enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    Associate = 0x03
}


pub struct SocksRequest {
    pub version: u8,
    pub command: SocksCommand,
    pub address: NetAddr,
    pub port: u16
}

#[derive(Clone, Copy, FromPrimitive)]
enum SocksAddrType {
    Ipv4 = 0x01,
    Name = 0x03,
    Ipv6 = 0x04
}

impl SocksRequest {
    pub fn parse<T: Read>(mut data: T) -> Option<SocksRequest> {
        let version = get!(data.read_u8());
        let command = num::FromPrimitive::from_u8(get!(data.read_u8()))?;
        let _reserved = get!(data.read_u8());
        let address = match num::FromPrimitive::from_u8(get!(data.read_u8()))? {
            SocksAddrType::Ipv4 => 
                NetAddr::V4(Ipv4Addr::from(
                    get!(data.read_u32::<NetworkEndian>()))),
            SocksAddrType::Ipv6 => {
                NetAddr::V6(Ipv6Addr::from([
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                    get!(data.read_u16::<NetworkEndian>()),
                ]))
            },
            SocksAddrType::Name => {
                let len = get!(data.read_u8());
                let bytes_opt: Vec<Option<u8>> = (0..len).map(
                                |_| Some(get!(data.read_u8()))).collect();
                if bytes_opt.contains(&None) {
                    return None;
                }
                let bytes = bytes_opt.into_iter().map(|x| x.unwrap()).collect();
                NetAddr::Name(get!(String::from_utf8(bytes)))
            },
        };

        let port = get!(data.read_u16::<NetworkEndian>());

        Some(SocksRequest{version, command, address, port})
    }
}


#[derive(Clone, Copy)]
pub enum SocksReplyStatus {
    Success = 0x00,
    Failure = 0x01
}

pub struct SocksReply {
    pub version: u8,
    pub status: SocksReplyStatus,
    pub address: NetAddr,
    pub port: u16
}

impl SocksReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.version, self.status as u8];

        match &self.address {
            &NetAddr::V4(addr) => {
                res.push(SocksAddrType::Ipv4 as u8);
                res.extend(addr.octets().iter());
            },
            &NetAddr::V6(addr) => {
                res.push(SocksAddrType::Ipv6 as u8);
                res.extend(addr.octets().iter());
            },
            &NetAddr::Name(ref name) => {
                res.push(SocksAddrType::Name as u8);
                if name.len() > 255 {
                    panic!("Name is too long");
                }
                res.push(name.len() as u8);
                res.extend(name.as_bytes().iter());
            },
        }

        res.push((self.port >> 8) as u8);
        res.push((self.port & 0xff) as u8);
        
        res
    }
}
