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

//! This file uses some code from Rustls.
//! MIT License.

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;
use std::str;

mod tcpserver_mio;
use crate::tcpserver_mio::TcpServerMio;

mod ds;
mod ds_interface;
mod fcm;

const USAGE: &str = "
Runs the Privastead server on :PORT.

Usage:
  privastead-server (-p PORT | --port PORT)
  privastead-server (--version | -v)
  privastead-server (--help | -h)

Options:
    -p, --port PORT     Listen on PORT.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: u16,
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let mut tcpserver_mio = TcpServerMio::new(args.flag_port);
    tcpserver_mio.listen();
}
