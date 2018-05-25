use std::ops::Drop;
use std::io::Write;

use conn::Connection;


pub struct SocksHandlerFactory {

}

pub struct SocksHandler {
    counter: usize
}

impl SocksHandlerFactory {
    pub fn new() -> SocksHandlerFactory {
        SocksHandlerFactory{}
    }

    pub fn new_handler(&self, conn: &Connection) -> SocksHandler {
        SocksHandler::new(conn)
    }
}

impl SocksHandler {
    pub fn new(conn: &Connection) -> SocksHandler {
        eprintln!("Created handler for {:?}", conn.addr());
        SocksHandler{ counter: 0 }
    }

    pub fn handle_connection_data(&mut self, conn: &mut Connection, data: &[u8])
    {
        self.counter += data.len();
        let msg = format!("Bytes read: {}\n", self.counter);
        conn.write(msg.as_bytes()).unwrap_or_else(|err| {
            eprintln!("Failed to send data: {:?}", err);
            0
        });
    }
}

impl Drop for SocksHandler {
    fn drop(&mut self) {
        eprintln!("Dropped handler");
    }
}
