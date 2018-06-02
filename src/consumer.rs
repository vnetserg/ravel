use std::rc::Rc;
use std::boxed::Box;
use std::cell::RefCell;
use std::io::Read;

use socks::data::NetAddr;
use conn::Connection;


pub enum ConsumerRequest {
    Connect(NetAddr, u16),
    Close
}


pub enum ConsumerStatus {
    Hold,
    Next(Box<Consumer>),
    Failure(String),
}


pub trait Consumer {
    fn take(&mut self, conn: Rc<RefCell<Connection>>, data: &mut Read,
                       requests: &mut Vec<ConsumerRequest>)
        -> ConsumerStatus;
}
