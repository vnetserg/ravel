use std::rc::Rc;
use std::boxed::Box;
use std::cell::RefCell;
use std::ops::Drop;
use std::io::{Write, Read};

use conn::Connection;
use consumer::{Consumer, ConsumerRequest, ConsumerStatus};
use socks::data::*;


pub struct SocksHandlerFactory {

}

impl SocksHandlerFactory {
    pub fn new() -> SocksHandlerFactory {
        SocksHandlerFactory{}
    }

    pub fn new_handler(&self, conn: Rc<RefCell<Connection>>) -> SocksHandler {
        SocksHandler::new(conn)
    }
}



pub struct SocksHandler {
    consumer: Box<Consumer>
}

impl SocksHandler {
    pub fn new(conn: Rc<RefCell<Connection>>) -> SocksHandler {
        eprintln!("Created handler for {}", conn.borrow().addr());
        SocksHandler{ consumer: Box::new(SocksInitStep{}) }
    }


    pub fn handle_connection_data(&mut self, conn: Rc<RefCell<Connection>>,
                                  mut data: &[u8])
        -> Vec<ConsumerRequest>
    {
        let mut requests = Vec::new();

        while !data.is_empty() {
            match self.consumer.take(conn.clone(), &mut data, &mut requests) {
                ConsumerStatus::Hold => { }
                ConsumerStatus::Next(cons) => self.consumer = cons,
                ConsumerStatus::Failure(err) => {
                    eprintln!("Handler error: {}", err);
                    return vec![ConsumerRequest::Close];
                }
            }
        }

        requests
    }
}

impl Drop for SocksHandler {
    fn drop(&mut self) {
        eprintln!("Dropped handler");
    }
}


struct SocksInitStep {}

impl Consumer for SocksInitStep {
    fn take(&mut self, conn: Rc<RefCell<Connection>>, data: &mut Read,
                     _requests: &mut Vec<ConsumerRequest>)
        -> ConsumerStatus
    {
        let mut conn = conn.borrow_mut();
        let auth = match AuthRequest::parse(data) {
            Some(auth) => auth,
            None => {
                return ConsumerStatus::Failure(
                    "Invalid AuthRequest, closing connection".to_string());
            }
        };

        if auth.version != 5 {
            return ConsumerStatus::Failure(
                format!("Unsupported socks version: {}", auth.version));
        }

        if !auth.methods.contains(&AuthMethod::Unauthorized) {
            let reply = AuthReply{version: 5, method: AuthMethod::NoMethod};
            let _ = conn.write(&reply.to_bytes());
            return ConsumerStatus::Failure("No supported auth method"
                                           .to_string());
        }

        let reply = AuthReply{version: 5, method: AuthMethod::Unauthorized};
        if let Err(err) = conn.write(&reply.to_bytes()) {
            return ConsumerStatus::Failure(
                format!("Failed to write to socket: {}", err));
        }

        eprintln!("Auth negotiation successfull");
        return ConsumerStatus::Next(Box::new(SocksRequestStep{}));
    }
}


struct SocksRequestStep {}

impl Consumer for SocksRequestStep {
    fn take(&mut self, conn: Rc<RefCell<Connection>>, data: &mut Read,
                     requests: &mut Vec<ConsumerRequest>)
        -> ConsumerStatus
    {
        let mut conn = conn.borrow_mut();
        let socks = match SocksRequest::parse(data) {
            Some(socks) => socks,
            None => return ConsumerStatus::Failure(
                "Invalid socks request, closing".to_string()),
        };

        if socks.version != 5 {
            return ConsumerStatus::Failure(
                format!("Unsupported socks version: {}", socks.version));
        }

        if let SocksCommand::Connect = socks.command {
            let reply = SocksReply {
                version: 5,
                status: SocksReplyStatus::Success,
                address: socks.address.clone(),
                port: socks.port
            };
            if let Err(err) = conn.write(&reply.to_bytes()) {
                return ConsumerStatus::Failure(
                    format!("Failed to write to socket: {}", err));
            }
            requests.push(ConsumerRequest::Connect(socks.address, socks.port));
            return ConsumerStatus::Next(Box::new(SocksConnectStep{}));
        } else {
            return ConsumerStatus::Failure(
                format!("Unsupported socks command"));
        }
    }
}


struct SocksConnectStep {}

impl Consumer for SocksConnectStep {
    fn take(&mut self, conn: Rc<RefCell<Connection>>, data: &mut Read,
                     _requests: &mut Vec<ConsumerRequest>)
        -> ConsumerStatus
    {
        let mut buf = vec![];
        data.read_to_end(&mut buf).unwrap();

        let mut conn = conn.borrow_mut();
        if let Err(err) = conn.write(&buf) {
            return ConsumerStatus::Failure(
                format!("Failed to write to socket: {}", err));
        } else {
            return ConsumerStatus::Hold;
        }
    }
}
