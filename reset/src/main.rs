//! Privastead reset button listener.
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

use rppal::gpio::{Gpio, Trigger};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
    process::{Command, Stdio},
};
use std::sync::atomic::{AtomicBool, Ordering};

fn run_command_to_completion(command: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .current_dir("/home/privastead/privastead/camera_hub")
        .arg(command)
        .output()
        .expect("failed to execute process");

    println!("Status: {}", output.status);

    println!(
        "Stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    println!(
        "Stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn reset_action() {
    // First, stop the privastead service
    run_command_to_completion("sudo systemctl stop privastead.service");
    // Second, reset privastead camera hub
    run_command_to_completion("sudo LD_LIBRARY_PATH=/usr/local/lib/aarch64-linux-gnu/:${LD_LIBRARY_PATH:-} /home/privastead/privastead/camera_hub/target/release/privastead-camera-hub --reset-full");
    // Finally, start the privastead service
    run_command_to_completion("sudo systemctl start privastead.service");
}

fn main() {
    let button_pin_number = 16;
    let led_pin_number = 25;

    let gpio = Gpio::new().expect("Failed to initialize GPIO");
    
    let mut button = gpio.get(button_pin_number).expect("Failed to get GPIO pin").into_input_pullup();
    button.set_interrupt(Trigger::Both, Some(Duration::from_millis(50)))
        .expect("Failed to set interrupt");

    let mut led = gpio
        .get(led_pin_number)
        .expect("Failed to get LED GPIO")
        .into_output();

    led.set_low();

    // Blink for 5 seconds at start
    for _ in 0..5 {
        led.set_high();
        thread::sleep(Duration::from_millis(500));
        led.set_low();
        thread::sleep(Duration::from_millis(500));
    }

    let button_held = Arc::new(Mutex::new(false));
    let last_press_time = Arc::new(Mutex::new(None));
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let led_shared = Arc::new(Mutex::new(led));

    println!("Waiting for button press...");

    loop {
        match button.poll_interrupt(true, None) {
            Ok(Some(_)) => {
                if button.is_low() {
                    let mut last_press = last_press_time.lock().unwrap();

                    if last_press.is_none() {
                        *last_press = Some(Instant::now());
                        println!("Button pressed!");

                        // Turn LED ON immediately
                        let mut led = led_shared.lock().unwrap();
                        led.set_high(); // LED ON
                        drop(led);

                        let button_held_clone = Arc::clone(&button_held);
                        let last_press_clone = Arc::clone(&last_press_time);
                        let cancel_flag_clone = Arc::clone(&cancel_flag);
                        let led_clone = Arc::clone(&led_shared);

                        cancel_flag_clone.store(false, Ordering::Relaxed);

                        thread::spawn(move || {
                            for _ in 0..500 {
                                thread::sleep(Duration::from_millis(10));
                                
                                if cancel_flag_clone.load(Ordering::Relaxed) {
                                    return;
                                }
                            }

                            if *button_held_clone.lock().unwrap() {
                                println!("Button held for 5 seconds!");
                                thread::spawn(|| {
                                    reset_action();
                                });                                

                                // Blink for 5 seconds
                                let mut led = led_clone.lock().unwrap();
                                for _ in 0..10 {
                                    led.set_low();
                                    thread::sleep(Duration::from_millis(250));
                                    led.set_high();
                                    thread::sleep(Duration::from_millis(250));
                                }
                                drop(led);
                            }

                            *last_press_clone.lock().unwrap() = None;
                        });
                    }

                    *button_held.lock().unwrap() = true;
                } else {
                    println!("Button released!");
                    *button_held.lock().unwrap() = false;
                    *last_press_time.lock().unwrap() = None;
                    cancel_flag.store(true, Ordering::Relaxed);

                    // Turn LED OFF
                    let mut led = led_shared.lock().unwrap();
                    led.set_low();
                    drop(led);
                }
            }
            Ok(None) => {} // No event
            Err(e) => eprintln!("Error polling interrupt: {:?}", e),
        }
    }
}
