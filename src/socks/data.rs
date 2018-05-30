use std::io::Read;
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
    pub fn parse<T: Read>(mut data: T) -> Option<AuthRequest> {
        let version = get!(data.read_u8());
        let n_methods = get!(data.read_u8());
        let methods: Vec<Option<AuthMethod>> = (0..n_methods).map(|_|
            match get!(data.read_u8()) {
                0 => Some(AuthMethod::Unauthorized),
                _ => Some(AuthMethod::Other)
            }
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
    pub fn parse<T: Read>(mut data: T) -> Option<SocksRequest> {
        let version = get!(data.read_u8());
        let command = match get!(data.read_u8()) {
            CMD_CONNECT => SocksCommand::Connect,
            CMD_BIND => SocksCommand::Bind,
            CMD_ASSOCIATE => SocksCommand::Associate,
            _ => return None,
        };

        let _reserved = get!(data.read_u8());
        let address = match get!(data.read_u8()) {
            ATYP_IPV4 => NetAddr::V4(Ipv4Addr::from(
                                get!(data.read_u32::<NetworkEndian>()))),
            ATYP_IPV6 => {
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
            ATYP_NAME => {
                let len = get!(data.read_u8());
                let bytes_opt: Vec<Option<u8>> = (0..len).map(
                                |_| Some(get!(data.read_u8()))).collect();
                if bytes_opt.contains(&None) {
                    return None;
                }
                let bytes = bytes_opt.into_iter().map(|x| x.unwrap()).collect();
                NetAddr::Name(get!(String::from_utf8(bytes)))
            },
            _ => return None,
        };

        let port = get!(data.read_u16::<NetworkEndian>());

        Some(SocksRequest{version, command, address, port})
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
