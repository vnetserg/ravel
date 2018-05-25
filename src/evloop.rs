use std::io;
use std::io::Read;

use mio::{Token, Poll, Events, Ready, PollOpt};
use mio::net::TcpListener;

use slab::Slab;

use conn::{ Connection, ConnSource };
use dispatcher::Dispatcher;


const BUFFER_SIZE: usize = 2048;

pub struct EventLoop {
    poll: Poll,
    dispatcher: Dispatcher,
    listeners: Slab<TcpListener>,
    connections: Slab<Connection>,
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
                        |err| eprintln!("Connection failed: {:?}", err));
                } else {
                    self.handle_connection_readable((id-1)/2).unwrap_or_else(
                        |err| eprintln!("Connection failed: {:?}", err));
                }
            }
        }
    }

    fn handle_new_connection(&mut self, listener_id: usize)
        -> Result<(), io::Error>
    {
        let (stream, addr) = self.listeners.get(listener_id).unwrap().accept()?;
        eprintln!("New connection from {:?}", addr);

        let id = self.connections.insert(Connection::new(stream, addr,
                                         ConnSource::Listener(listener_id)));
        let conn = self.connections.get_mut(id).unwrap();

        self.poll.register(conn.stream(), Token(2 * id + 1),
                           Ready::readable(), PollOpt::level())?;

        self.dispatcher.handle_new_connection(conn);

        Ok(())
    }

    fn handle_connection_readable(&mut self, id: usize)
        -> Result<(), io::Error>
    {
        let len = self.connections.get_mut(id).unwrap() 
                        .read(&mut self.read_buffer)?;

        if len == 0 {
            let mut conn = self.connections.remove(id);
            self.dispatcher.handle_drop_connection(&mut conn);
            eprintln!("Connection closed: {:?}", conn.addr());
        } else {
            let conn = self.connections.get_mut(id).unwrap();
            self.dispatcher.handle_connection_data(conn,
                                                   &self.read_buffer[..len]);
            eprintln!("Got {} bytes from {}", len, conn.addr());
        }
        
        Ok(())
    }
}
