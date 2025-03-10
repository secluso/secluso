//! Privastead DS Interface.
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

use crate::ds::DeliveryService;
use privastead_client_server_lib::ops::{
    DEREGISTER_CLIENT, RECV_MSGS, REGISTER_CLIENT, SEND_MSG, SEND_NOTIF, UPDATE_TOKEN,
};
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

pub struct DsInterface {
    ds: Rc<RefCell<DeliveryService>>,
}

impl DsInterface {
    pub fn new(ds: Rc<RefCell<DeliveryService>>) -> Self {
        Self { ds }
    }

    /// Incoming message in buf. If there's a response, insert in resp_buf.
    /// Return true to keep the connection alive. Return false to close it.
    pub fn process_incoming_data(&self, buf: &[u8], resp_buf: &mut Vec<u8>) -> io::Result<()> {
        let op = buf[buf.len() - 1];

        match op {
            REGISTER_CLIENT => {
                self.ds
                    .borrow_mut()
                    .register_client(&buf[..buf.len() - 1], resp_buf);
            }
            DEREGISTER_CLIENT => {
                self.ds
                    .borrow_mut()
                    .deregister_client(&buf[..buf.len() - 1], resp_buf);
            }
            UPDATE_TOKEN => {
                self.ds
                    .borrow_mut()
                    .update_token(&buf[..buf.len() - 1], resp_buf);
            }
            SEND_MSG => {
                self.ds
                    .borrow_mut()
                    .send_msg(&buf[..buf.len() - 1], resp_buf, false);
            }
            RECV_MSGS => {
                self.ds
                    .borrow_mut()
                    .recv_msgs(&buf[..buf.len() - 1], resp_buf);
            }
            SEND_NOTIF => {
                self.ds
                    .borrow_mut()
                    .send_msg(&buf[..buf.len() - 1], resp_buf, true);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid op code.",
                ));
            }
        }

        Ok(())
    }
}
