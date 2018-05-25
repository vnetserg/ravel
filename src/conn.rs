use std::net::SocketAddr;
use std::io;

use mio::{Evented, Token, Poll, PollOpt, Ready};
use mio::net::TcpStream;

pub struct Connection {
    id: usize,
    listener: Option<usize>,
    addr: SocketAddr,
    stream: TcpStream,
}

impl Connection {
    pub fn new(id: usize, listener: usize, stream: TcpStream,
               addr: SocketAddr) -> Connection
    {
        let listener = Some(listener);
        Connection{ id, listener, addr, stream }
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
    
    pub fn id(&self) -> usize {
        self.id
    }

    pub fn listener(&self) -> Option<usize> {
        self.listener
    }
}

impl io::Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
} 

impl io::Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Evented for Connection {
    fn register(&self, poll: &Poll, token: Token, interest: Ready,
                opts: PollOpt) -> io::Result<()>
    {
        self.stream.register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready,
                opts: PollOpt) -> io::Result<()>
    {
        self.stream.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        self.stream.deregister(poll)
    }
}
