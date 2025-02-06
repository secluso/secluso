//! Privastead TCP Server.
//!
//! Copyright (C) 2024  Ardalan Amiri Sani
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! This file uses some code from a TLS server from Rustls.
//! MIT License.

use crate::ds::DeliveryService;
use crate::ds_interface::DsInterface;
use chrono::Utc;
use mio::net::{TcpListener, TcpStream};
use privastead_client_server_lib::auth::{ServerAuth, NUM_SECRET_BYTES, NUM_USERNAME_BYTES};
use privastead_client_server_lib::ops::{
    DO_AUTH, GET_NONCE, KEEP_ALIVE, KEEP_ALIVE_NO, KEEP_ALIVE_YES,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net;
use std::rc::Rc;

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

#[derive(PartialEq)]
enum AuthStatus {
    NotAttempted,
    Ongoing,
    Successful,
    Unsuccessful,
}

/// This binds together a TCP listening socket and some outstanding
/// connections.
struct TcpServer {
    server: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    ds_all: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], Rc<RefCell<DeliveryService>>>>>,
    users: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]>>>,
}

impl TcpServer {
    fn new(server: TcpListener) -> Self {
        let (users, ds_all) = Self::get_users();
        Self {
            server,
            connections: HashMap::new(),
            next_id: 2,
            ds_all: Rc::new(RefCell::new(ds_all)),
            users: Rc::new(RefCell::new(users)),
        }
    }

    fn get_ds_directory_pathname(username: [u8; NUM_USERNAME_BYTES]) -> String {
        let username_string: String = username
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();
        "./ds_all_state/".to_string() + &username_string
    }

    fn get_users() -> (
        HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]>,
        HashMap<[u8; NUM_USERNAME_BYTES], Rc<RefCell<DeliveryService>>>,
    ) {
        let mut users: HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]> = HashMap::new();
        let mut ds_all: HashMap<[u8; NUM_USERNAME_BYTES], Rc<RefCell<DeliveryService>>> =
            HashMap::new();

        match fs::read_dir("./user_credentials") {
            Ok(files) => {
                for file in files {
                    match file {
                        Ok(f) => {
                            match f.file_type() {
                                Ok(file_type) => {
                                    //Ignore dir, symlink, etc.
                                    if file_type.is_file() {
                                        let mut pathname = OsString::from("./user_credentials/");
                                        pathname.push(f.file_name());
                                        let fil =
                                            fs::File::open(pathname).expect("Could not open file");
                                        let mut reader = BufReader::with_capacity(
                                            fil.metadata().unwrap().len().try_into().unwrap(),
                                            fil,
                                        );
                                        let credentials = reader.fill_buf().unwrap();
                                        assert!(
                                            credentials.len()
                                                == (NUM_USERNAME_BYTES + NUM_SECRET_BYTES)
                                        );
                                        let username: [u8; NUM_USERNAME_BYTES] =
                                            credentials[..NUM_USERNAME_BYTES].try_into().unwrap();
                                        let secret: [u8; NUM_SECRET_BYTES] = credentials
                                            [NUM_USERNAME_BYTES
                                                ..NUM_USERNAME_BYTES + NUM_SECRET_BYTES]
                                            .try_into()
                                            .unwrap();
                                        log::debug!("Loading info for user {:?}", username);
                                        let old = users.insert(username, secret);
                                        if old.is_some() {
                                            panic!("Duplicate user in users!");
                                        }

                                        // Generate directory pathname for ds to use
                                        let ds_dir = Self::get_ds_directory_pathname(username);
                                        let old_ds = ds_all.insert(
                                            username,
                                            Rc::new(RefCell::new(DeliveryService::new(ds_dir))),
                                        );
                                        if old_ds.is_some() {
                                            panic!("Duplicate user in ds_all!");
                                        }
                                    }
                                }
                                Err(e) => {
                                    panic!("Could not get file type: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            panic!("This may have to do with you not putting your user_credentials file within a folder called user_credentials (the file can be renamed to anything). Could not read file from directory: {:?}", e);
                        }
                    }
                }
            }
            Err(e) => {
                panic!("Could not read directory: {:?}", e);
            }
        }

        (users, ds_all)
    }

    fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {:?}", addr);

                    let token = mio::Token(self.next_id);
                    self.next_id += 1;

                    let mut connection = OpenConnection::new(
                        socket,
                        token,
                        Rc::clone(&self.ds_all),
                        Rc::clone(&self.users),
                    );
                    connection.register(registry);
                    self.connections.insert(token, connection);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    log::debug!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }

    fn drop_inactive_conns(&mut self) {
        let current_timestamp = Utc::now().timestamp();
        self.connections.retain(|_token, conn| {
            !(conn.keep_alive.is_some()
                && !conn.keep_alive.unwrap()
                && (current_timestamp - conn.last_conn_timestamp > 30))
        });
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream and some other state/metadata.
struct OpenConnection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    // keep outgoing data here until we can write
    outgoing_data: Vec<u8>,
    // keep partially received incoming data here until we receive all
    incoming_data: Vec<u8>,
    ds_all: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], Rc<RefCell<DeliveryService>>>>>,
    ds_interface: Option<DsInterface>,
    server_auth: Option<ServerAuth>,
    auth_status: AuthStatus,
    users: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]>>>,
    keep_alive: Option<bool>,
    last_conn_timestamp: i64,
}

impl OpenConnection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        ds_all: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], Rc<RefCell<DeliveryService>>>>>,
        users: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]>>>,
    ) -> Self {
        Self {
            socket,
            token,
            closing: false,
            closed: false,
            outgoing_data: Vec::new(),
            incoming_data: Vec::new(),
            ds_all,
            ds_interface: None,
            server_auth: None,
            auth_status: AuthStatus::NotAttempted,
            users,
            keep_alive: None,
            last_conn_timestamp: Utc::now().timestamp(),
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, registry: &mio::Registry, ev: &mio::event::Event) {
        self.last_conn_timestamp = Utc::now().timestamp();

        if ev.is_readable() {
            // Auth check
            if self.auth_status == AuthStatus::Unsuccessful {
                error!("Unauthenticated client");
                self.closing = true;
                return;
            }

            // Read some data.
            // A little big bigger than the video chunks sent by the camera
            let mut data = vec![0; 9 * 1024];

            match self.socket.read(&mut data) {
                Ok(0) => {
                    debug!("eof");
                    self.closing = true;
                    return;
                }

                Ok(n) => {
                    //FIXME: use extend_from_slice()?
                    self.incoming_data.append(&mut data[..n].to_vec());

                    let mut rc = true;
                    while rc && !self.incoming_data.is_empty() {
                        rc = self.read_varying_len();
                    }
                }

                Err(err) => {
                    if err.kind() != io::ErrorKind::WouldBlock {
                        if err.kind() != io::ErrorKind::ConnectionReset {
                            error!("read error {:?}", err);
                        }
                        self.closing = true;
                    }
                }
            }
        }

        if ev.is_writable() {
            // Auth check
            if self.auth_status == AuthStatus::Unsuccessful {
                error!("Unauthenticated client");
                self.closing = true;
                return;
            }

            // Write pending outgoing data.
            match self.write_varying_len() {
                Ok(_) => {}
                Err(err) => {
                    if err.kind() != io::ErrorKind::WouldBlock {
                        error!("write failed {:?}", err);
                        self.closing = true;
                    }
                }
            }
            self.outgoing_data = Vec::new();
        }

        if self.closing {
            let _ = self.socket.shutdown(net::Shutdown::Both);
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    /// Process some amount of received data.
    fn process_incoming_data(&self, buf: &[u8]) -> io::Result<Vec<u8>> {
        let mut resp_buf = Vec::new();
        match self
            .ds_interface
            .as_ref()
            .unwrap()
            .process_incoming_data(buf, &mut resp_buf)
        {
            Ok(_) => {
                Ok(resp_buf)
            }
            Err(e) => Err(e),
        }
    }

    fn write_varying_len(&mut self) -> io::Result<()> {
        // FIXME: is u64 necessary?
        let len = self.outgoing_data.len() as u64;
        let len_data = len.to_be_bytes();

        self.socket.write_all(&len_data)?;
        self.socket.write_all(&self.outgoing_data)?;

        Ok(())
    }

    fn process_first_auth_msg(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        if buf.len() != 1 {
            debug!("Invalid msg: expected len 1 for first message");
            self.auth_status = AuthStatus::Unsuccessful;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid length.",
            ));
        }

        let op = buf[0];

        if op != GET_NONCE {
            debug!("Invalid msg: expected GET_NONCE");
            self.auth_status = AuthStatus::Unsuccessful;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid op."));
        }

        if self.server_auth.is_some() {
            debug!("Unexpected: server_auth is some.");
            self.auth_status = AuthStatus::Unsuccessful;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid server_auth status.",
            ));
        }

        self.server_auth = Some(ServerAuth::new(Rc::clone(&self.users)));

        let resp_buf = self.server_auth.as_ref().unwrap().generate_msg_to_user();

        self.auth_status = AuthStatus::Ongoing;

        Ok(resp_buf)
    }

    fn process_second_auth_msg(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        //FIXME: check lengh.
        let op = buf[buf.len() - 1];

        if op != DO_AUTH {
            debug!("Invalid msg: expected DO_AUTH");
            self.auth_status = AuthStatus::Unsuccessful;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid op."));
        }

        if self.server_auth.is_none() {
            debug!("Unexpected: server_auth is none.");
            self.auth_status = AuthStatus::Unsuccessful;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid server_auth status.",
            ));
        }

        match self
            .server_auth
            .as_ref()
            .unwrap()
            .authenticate_user_msg(buf[..buf.len() - 1].to_vec())
        {
            Ok(username) => {
                // Get the ds for this user
                self.ds_interface = Some(DsInterface::new(Rc::clone(
                    self.ds_all.borrow_mut().get(&username).unwrap(),
                )));

                let resp_buf = vec![0u8];
                self.auth_status = AuthStatus::Successful;
                Ok(resp_buf)
            }
            Err(err) => {
                self.auth_status = AuthStatus::Unsuccessful;
                Err(err)
            }
        }
    }

    fn process_keep_alive_msg(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        if buf.len() != 2 {
            debug!("Invalid len for KEEP_ALIVE message");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid len for KEEP_ALIVE.",
            ));
        }

        let op = buf[buf.len() - 1];

        if op != KEEP_ALIVE {
            debug!("Invalid msg: expected KEEP_ALIVE");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid op."));
        }

        if self.keep_alive.is_some() {
            debug!("Unexpected: keep_alive already set.");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid keep_alive status.",
            ));
        }

        let keep_alive = buf[0];

        if keep_alive == KEEP_ALIVE_YES {
            self.keep_alive = Some(true);
        } else if keep_alive == KEEP_ALIVE_NO {
            self.keep_alive = Some(false);
        } else {
            debug!("Invalid keep_alive payload.");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid keep_alive payload.",
            ));
        }

        let resp_buf = vec![0u8];
        Ok(resp_buf)
    }

    fn process_one_transaction(&mut self, len: usize) -> io::Result<()> {
        self.incoming_data.drain(..8);

        let resp = if self.auth_status == AuthStatus::NotAttempted {
            self.process_first_auth_msg(&self.incoming_data[..len].to_vec())
        } else if self.auth_status == AuthStatus::Ongoing {
            self.process_second_auth_msg(&self.incoming_data[..len].to_vec())
        } else if self.keep_alive.is_none() {
            //Right after authentication, the client needs to tell us whether this
            //connection needs to be kept alive if idle.
            self.process_keep_alive_msg(&self.incoming_data[..len].to_vec())
        } else {
            self.process_incoming_data(&self.incoming_data[..len])
        };

        self.incoming_data.drain(..len);

        match resp {
            Ok(mut buf) => {
                if !buf.is_empty() {
                    self.outgoing_data.append(&mut buf);
                }

                Ok(())
            }
            Err(err) => {
                Err(err)
            }
        }
    }

    fn read_varying_len(&mut self) -> bool {
        // Auth check: we need to check here too to make sure no messages after a failed
        // auth attempt gets processed.
        if self.auth_status == AuthStatus::Unsuccessful {
            error!("Unauthenticated client");
            self.closing = true;
            return false;
        }

        if self.incoming_data.len() < 8 {
            return false;
        }

        let len_data: [u8; 8] = self.incoming_data[..8].try_into().unwrap();
        let len = u64::from_be_bytes(len_data) as usize;

        if len == 0 {
            error!("Invalid len!");
            self.closing = true;
            false
        } else if len > (self.incoming_data.len() - 8) {
            // Haven't received a full transaction
            return false;
        } else if len == (self.incoming_data.len() - 8) {
            // Have received just one transaction
            match self.process_one_transaction(len) {
                Ok(_) => {}
                Err(e) => {
                    error!("Transaction failed: {e}");
                    self.closing = true;
                }
            }

            return false;
        } else {
            // Have received more than one transaction
            match self.process_one_transaction(len) {
                Ok(_) => {}
                Err(e) => {
                    error!("Transaction failed: {e}");
                    self.closing = true;
                    return false;
                }
            }

            return true;
        }
    }

    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn reregister(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry.deregister(&mut self.socket).unwrap();
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Interest {
        let rd = true;
        let wr = !self.outgoing_data.is_empty();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(net::Shutdown::Both);
        self.closed = true;
    }
}

pub struct TcpServerMio {
    tcpserver: TcpServer,
    poll: mio::Poll,
    events: mio::Events,
}

impl TcpServerMio {
    pub fn new(port: u16) -> Self {
        // FIXME: use input port here.
        let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
        addr.set_port(port);

        let mut listener = TcpListener::bind(addr).expect("cannot listen on port");
        let pll = mio::Poll::new().unwrap();
        pll.registry()
            .register(&mut listener, LISTENER, mio::Interest::READABLE)
            .unwrap();

        let tcpserv = TcpServer::new(listener);

        let evts = mio::Events::with_capacity(256);
        Self {
            tcpserver: tcpserv,
            poll: pll,
            events: evts,
        }
    }

    pub fn listen(&mut self) {
        loop {
            self.poll.poll(&mut self.events, None).unwrap();

            for event in self.events.iter() {
                match event.token() {
                    LISTENER => {
                        self.tcpserver
                            .accept(self.poll.registry())
                            .expect("error accepting socket");
                    }
                    _ => self.tcpserver.conn_event(self.poll.registry(), event),
                }
            }

            //FIXME: too often? And what if there's no event to trigger this?
            self.tcpserver.drop_inactive_conns();
        }
    }
}
