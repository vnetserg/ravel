use std::net::SocketAddr;
use std::io;

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

    pub fn stream(&mut self) -> &mut TcpStream {
        &mut self.stream
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
