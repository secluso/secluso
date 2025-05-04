//! Privastead fault injection code.
//!
//! Copyright (C) 2025  Ardalan Amiri Sani
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

#[macro_export]
macro_rules! inject_fault {
    ($tag:expr) => {
        #[cfg(debug_assertions)]
        {
            use std::env;
            match env::var("INJECT_FAULT") {
                Ok(val) => {
                    if val == $tag.to_string() {
                        println!("INJECT_FAULT detected: {}", val);
                        std::process::exit(1);
                    }
                }
                Err(_) => {},
            }
        }
        #[cfg(not(debug_assertions))]
        {
        }
    };
}