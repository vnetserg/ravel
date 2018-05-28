use std::ops::Drop;
use std::io::Write;

use conn::Connection;


const SOCKS_V5: u8 = 0x05;
const NO_AUTH: u8 = 0x00;


pub struct SocksHandlerFactory {

}

impl SocksHandlerFactory {
    pub fn new() -> SocksHandlerFactory {
        SocksHandlerFactory{}
    }

    pub fn new_handler(&self, conn: &Connection) -> SocksHandler {
        SocksHandler::new(conn)
    }
}


pub enum SocksHandlerState {
    WaitForAuth,
    WaitForRequest,
    Closed
}


pub struct SocksHandler {
    state: SocksHandlerState,
}

impl SocksHandler {
    pub fn new(conn: &Connection) -> SocksHandler {
        eprintln!("Created handler for {:?}", conn.addr());
        SocksHandler{ state: SocksHandlerState::WaitForAuth }
    }

    pub fn handle_connection_data<'a, 'b, 'c>(&'a mut self,
                                              conn: &'b mut Connection,
                                              mut data: &'c [u8])
    {
        while data.len() > 0 {
            data = match self.state {
                SocksHandlerState::WaitForAuth =>
                    self.handle_auth_data(conn, data),
                SocksHandlerState::WaitForRequest => {
                    conn.write(data).unwrap_or_else(|err| {
                        eprintln!("Failed to write to socket: {}", err);
                        0
                    });
                    &[]
                }
                SocksHandlerState::Closed => break,
            }
        }
    }

    fn handle_auth_data<'a, 'b, 'c>(&'a mut self, conn: &'b mut Connection,
                                    data: &'c[u8]) -> &'c[u8]
    {
        if data.len() < 2 {
            eprintln!("Error: got only {} bytes in WaitForAuth state",
                     data.len());
            self.close();
            return &[];
        }

        let (&socks_ver, data) = data.split_first().unwrap();
        let (&n_methods, data) = data.split_first().unwrap();
        if socks_ver != SOCKS_V5 {
            eprintln!("Error: got {} socks version", socks_ver);
            self.close();
            return &[];
        }

        if data.len() < n_methods as usize {
            eprintln!("Error: got {} methods, expected {}",
                     data.len(), n_methods);
            self.close();
            return &[];
        }

        for i in 0 .. n_methods {
            if data[i as usize] == NO_AUTH {
                eprintln!("Auth method negotiation successfull");
                conn.write(&[SOCKS_V5, NO_AUTH]).unwrap_or_else(|err| {
                    eprintln!("Failed to write to socket: {}", err);
                    0
                });
                self.state = SocksHandlerState::WaitForRequest;
                return &data[n_methods as usize ..];
            }
        }

        eprintln!("Error: no supported auth method");
        self.close();
        return &[];
    }

    pub fn close(&mut self) {
        self.state = SocksHandlerState::Closed;
    }

    pub fn state(&self) -> &SocksHandlerState {
        &self.state
    }

    pub fn is_closed(&self) -> bool {
        if let SocksHandlerState::Closed = self.state {
            true
        } else {
            false
        }
    }
}

impl Drop for SocksHandler {
    fn drop(&mut self) {
        eprintln!("Dropped handler");
    }
}
