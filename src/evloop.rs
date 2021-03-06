use std::io;
use std::rc::Rc;
use std::io::Read;
use std::cell::RefCell;

use mio::{Token, Poll, Events, Ready, PollOpt};
use mio::net::TcpListener;

use slab::Slab;

use conn::Connection;
use dispatcher::{Dispatcher, DispatcherRequest};


const BUFFER_SIZE: usize = 2048;

pub struct EventLoop {
    poll: Poll,
    dispatcher: Dispatcher,
    listeners: Slab<TcpListener>,
    connections: Slab<Rc<RefCell<Connection>>>,
    read_buffer: [u8; BUFFER_SIZE],
}

impl EventLoop {
    pub fn new(dispatcher: Dispatcher) -> EventLoop {
        let poll = Poll::new().unwrap();
        let connections = Slab::new();
        let listeners = Slab::new();
        let read_buffer = [0; BUFFER_SIZE];
        EventLoop{ poll, dispatcher, listeners, connections, read_buffer }
    }

    pub fn add_listener(&mut self, listener: TcpListener)
        -> Result<(), io::Error>
    {
        let id = self.listeners.insert(listener);
        self.poll.register(self.listeners.get(id).unwrap(), Token(2*id),
                      Ready::readable(), PollOpt::edge())?;
        Ok(())
    }

    pub fn run(&mut self) -> ! {
        let mut events = Events::with_capacity(1024);
        loop {
            self.poll.poll(&mut events, None).unwrap();
            for event in events.iter() {
                let Token(id) = event.token();
                if id % 2 == 0 {
                    self.handle_new_connection(id/2).unwrap_or_else(
                        |err| eprintln!("Connection failed: {}", err));
                } else {
                    self.handle_connection_readable((id-1)/2).unwrap_or_else(
                        |err| eprintln!("Connection failed: {}", err));
                }
            }
        }
    }

    fn handle_new_connection(&mut self, listener_id: usize)
        -> Result<(), io::Error>
    {
        let (stream, addr) = self.listeners.get(listener_id).unwrap().accept()?;
        eprintln!("New connection from {}", addr);

        let entry = self.connections.vacant_entry();
        let id = entry.key();
        let conn = Connection::new(id, listener_id, stream, addr);
        let rc = Rc::new(RefCell::new(conn));
        let rc = entry.insert(rc);

        self.poll.register(&*rc.borrow(), Token(2 * id + 1),
                           Ready::readable(), PollOpt::edge())?;

        self.dispatcher.handle_new_connection(rc.clone());

        Ok(())
    }

    fn handle_connection_readable(&mut self, id: usize)
        -> Result<(), io::Error>
    {
        let len = self.connections.get_mut(id).unwrap().borrow_mut()
                        .read(&mut self.read_buffer)?;

        if len == 0 {
            let conn = self.connections.remove(id);
            self.dispatcher.handle_drop_connection(conn.clone());
            eprintln!("Connection closed: {}", conn.borrow().addr());
        } else {
            let requests = {
                let conn = self.connections.get_mut(id).unwrap();
                eprintln!("Got {} bytes from {}", len, conn.borrow().addr());
                let data = &self.read_buffer[..len];
                self.dispatcher.handle_connection_data(conn.clone(), data)
            };

            for req in requests {
                match req {
                    DispatcherRequest::Drop(id) => {
                        self.connections.remove(id);
                    },
                    DispatcherRequest::None => (),
                };
            }
        }
        
        Ok(())
    }
}
