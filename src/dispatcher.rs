use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;

use conn::Connection;
use socks::handler::{SocksHandlerFactory, SocksHandler};
use consumer::ConsumerRequest;

pub enum DispatcherRequest {
    Drop(usize),
    None
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

    pub fn handle_new_connection(&mut self, conn: Rc<RefCell<Connection>>) {
        self.handlers.insert(conn.borrow().id(),
                             self.factory.new_handler(conn.clone()));
    }

    pub fn handle_connection_data(&mut self, conn: Rc<RefCell<Connection>>,
                                  data: &[u8])
        -> Vec<DispatcherRequest>
    {
        eprintln!("Dispatcher received data");
        let handler_requests = {
            let handler = self.handlers.get_mut(&conn.borrow().id()).expect(
                            "Dispatcher got data from unexisting connection");
            handler.handle_connection_data(conn.clone(), data)
        };

        handler_requests.into_iter().map(|req|
            match req {
                ConsumerRequest::Close => {
                    eprintln!("Dispatcher dropping handler due to request");
                    self.handlers.remove(&conn.borrow().id());
                    DispatcherRequest::Drop(conn.borrow().id())
                },
                ConsumerRequest::Connect(addr, port) => {
                    eprintln!("Connect request: {:?} {}", addr, port);
                    DispatcherRequest::None
                }
            }
        ).collect()
    }

    pub fn handle_drop_connection(&mut self, conn: Rc<RefCell<Connection>>) {
        eprintln!("Dispatcher received drop event");
        self.handlers.remove(&conn.borrow().id());
    }
}
