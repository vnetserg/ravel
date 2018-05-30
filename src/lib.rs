extern crate mio;
extern crate num;
extern crate slab;
extern crate byteorder;

#[macro_use]
extern crate num_derive;

use std::net::SocketAddr;

use mio::net::TcpListener;

pub mod evloop;
pub mod dispatcher;
pub mod socks;
pub mod conn;

use evloop::EventLoop;
use dispatcher::Dispatcher;
use socks::handler::SocksHandlerFactory;

pub struct Config {
    pub addr: SocketAddr,
}

pub fn run(cfg: Config) {
    let handler_factory = SocksHandlerFactory::new();
    let dispatcher = Dispatcher::new(handler_factory);
    let mut evloop = EventLoop::new(dispatcher);

    let listener = TcpListener::bind(&cfg.addr).unwrap();
    evloop.add_listener(listener).unwrap();

    evloop.run();
}


