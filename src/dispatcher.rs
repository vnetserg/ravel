use std::io::Write;

use conn::Connection;
use socks_handler::SocksHandlerFactory;

pub struct Dispatcher {
    factory: SocksHandlerFactory
}

impl Dispatcher {
    pub fn new(factory: SocksHandlerFactory) -> Dispatcher {
        Dispatcher{ factory }
    }

    pub fn handle_new_connection(&mut self, conn: &mut Connection) {
        eprintln!("Dispatcher received connection");
    }

    pub fn handle_connection_data(&mut self, conn: &mut Connection, data: &[u8])
    {
        eprintln!("Dispatcher received data");
        conn.write(data).unwrap_or_else(|err| {
            eprintln!("Failed to write data: {}", err);
            0
        });
    }

    pub fn handle_drop_connection(&mut self, conn: &mut Connection, ) {
        eprintln!("Dispatcher received drop event");
    }
}
