use std::collections::HashMap;

use conn::Connection;
use socks_handler::{SocksHandlerFactory, SocksHandler};

pub enum DispatcherRequest {
    None,
    Drop(usize)
}

pub struct Dispatcher {
    factory: SocksHandlerFactory,
    handlers: HashMap<usize, SocksHandler>,
}

impl Dispatcher {
    pub fn new(factory: SocksHandlerFactory) -> Dispatcher {
        let handlers = HashMap::new();
        Dispatcher{ factory, handlers }
    }

    pub fn handle_new_connection(&mut self, conn: &mut Connection) {
        self.handlers.insert(conn.id(), self.factory.new_handler(conn));
    }

    pub fn handle_connection_data(&mut self, conn: &mut Connection, data: &[u8])
        -> DispatcherRequest
    {
        eprintln!("Dispatcher received data");
        let closed = {
            let handler = self.handlers.get_mut(&conn.id()).expect(
                            "Dispatcher got data from unexisting connection");
            handler.handle_connection_data(conn, data);
            handler.is_closed()
        };
        if closed {
            eprintln!("Dispatcher dropping handler due to request");
            self.handlers.remove(&conn.id());
            DispatcherRequest::Drop(conn.id())
        } else {
            DispatcherRequest::None
        }
    }

    pub fn handle_drop_connection(&mut self, conn: &mut Connection) {
        eprintln!("Dispatcher received drop event");
        self.handlers.remove(&conn.id());
    }
}
