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

//opcode for network messages
pub const REGISTER_CLIENT: u8 = 0;
pub const UPDATE_TOKEN: u8 = 1;
pub const SEND_MSG: u8 = 2;
pub const RECV_MSGS: u8 = 3;
pub const GET_NONCE: u8 = 4;
pub const DO_AUTH: u8 = 5;
pub const DEREGISTER_CLIENT: u8 = 6;
pub const SEND_NOTIF: u8 = 7;
pub const KEEP_ALIVE: u8 = 8;

//payload for the keep_alive message
pub const KEEP_ALIVE_YES: u8 = 0;
pub const KEEP_ALIVE_NO: u8 = 1;
