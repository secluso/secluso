//! Secluso fault injection code.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

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
                Err(_) => {}
            }
        }
        #[cfg(not(debug_assertions))]
        {}
    };
}
