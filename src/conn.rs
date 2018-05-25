use std::net::SocketAddr;
use std::io;

use mio::{Evented, Token, Poll, PollOpt, Ready};
use mio::net::TcpStream;

pub enum ConnSource {
    Listener(usize),
    Client(usize)
}

pub struct Connection {
    addr: SocketAddr,
    stream: TcpStream,
    source: ConnSource
}

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr, source: ConnSource)
        -> Connection
    {
        Connection{ addr, stream, source }
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn source(&self) -> &ConnSource {
        &self.source
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
