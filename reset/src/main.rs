//! Secluso reset button listener.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use base64::{engine::general_purpose, Engine as _};
use reqwest::blocking::{Body, Client};
use rppal::gpio::{Gpio, Trigger};
use std::collections::VecDeque;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Write;
use std::process::Command;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use secluso_client_server_lib::auth::parse_user_credentials_full;

const MULTI_PRESS_WINDOW: Duration = Duration::from_millis(5000);
const DEBUG_LOGS_FILENAME: &str = "debug_logs.txt";

fn run_command_to_completion(command: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .current_dir("/home/secluso/secluso/camera_hub")
        .arg(command)
        .output()
        .expect("failed to execute process");

    println!("Status: {}", output.status);

    println!("Stdout:\n{}", String::from_utf8_lossy(&output.stdout));

    println!("Stderr:\n{}", String::from_utf8_lossy(&output.stderr));
}

fn reset_action() {
    // First, stop the secluso service
    run_command_to_completion("sudo systemctl stop secluso.service");
    // Second, reset secluso camera hub
    run_command_to_completion("sudo LD_LIBRARY_PATH=/usr/local/lib/aarch64-linux-gnu/:${LD_LIBRARY_PATH:-} /home/secluso/secluso/camera_hub/target/release/secluso-camera-hub --reset-full");
    // The previous command, if run successfully, will delete the following three directories.
    // But we'll try to delete them again in case that command failed for some reason.
    run_command_to_completion("sudo rm -r /home/secluso/secluso/camera_hub/state");
    run_command_to_completion("sudo rm -r /home/secluso/secluso/camera_hub/pending_videos");
    run_command_to_completion("sudo rm -r /home/secluso/secluso/camera_hub/pending_thumbnails");
    // Finally, start the secluso service
    run_command_to_completion("sudo systemctl start secluso.service");
}

fn save_logs_to_file() -> io::Result<()> {
    let mut cmd = Command::new("journalctl");
    cmd.arg("--no-pager")
        .arg("--output=short-iso")
        .arg("-u")
        .arg("secluso.service")
        .arg("-n")
        .arg("10000"); // number of lines

    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("journalctl failed: {:?}", out.status.code()),
        ));
    }

    let mut file = File::create(DEBUG_LOGS_FILENAME)?;
    file.write_all(&out.stdout)?;
    Ok(())
}

pub fn upload_logs() -> io::Result<()> {
    // Read server info
    let credentials_full = fs::read("../camera_hub/credentials_full")?;
    let credentials_full_bytes = credentials_full.to_vec();
    let (server_username, server_password, server_addr) =
        parse_user_credentials_full(credentials_full_bytes).unwrap();

    if !server_addr.starts_with("https") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Upload_logs requires the server to use HTTPS",
        ));
    }

    let server_url = format!("{}/debug_logs", server_addr);
    println!("Uploading logs to {}", server_url);

    let file = File::open(DEBUG_LOGS_FILENAME)?;
    let reader = BufReader::new(file);

    let auth_value = format!("{}:{}", server_username, server_password);
    let auth_encoded = general_purpose::STANDARD.encode(auth_value);
    let auth_header = format!("Basic {}", auth_encoded);

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let response = client
        .post(server_url)
        .header("Content-Type", "application/octet-stream")
        .header("Authorization", auth_header)
        .body(Body::new(reader))
        .send()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Server error: {}", response.status()),
        ));
    }

    Ok(())
}

fn send_debug_logs_action() {
    // If reading the logs fail, we want to have some debug content to send
    if let Ok(mut file) = File::create(DEBUG_LOGS_FILENAME) {
        let _ = file.write_all(b"Empty");
    }

    if let Err(e) = save_logs_to_file() {
        println!("save_logs_to_file failed: {e}");
    }

    if let Err(e) = upload_logs() {
        println!("upload_logs failed: {e}");
    }
}

fn main() {
    let button_pin_number = 16;
    let led_pin_number = 25;

    let gpio = Gpio::new().expect("Failed to initialize GPIO");

    let mut button = gpio
        .get(button_pin_number)
        .expect("Failed to get GPIO pin")
        .into_input_pullup();
    button
        .set_interrupt(Trigger::Both, Some(Duration::from_millis(50)))
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

    // Keep recent press (release) timestamps
    let mut recent_presses: VecDeque<Instant> = VecDeque::new();

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
                                    led.set_high();
                                    thread::sleep(Duration::from_millis(250));
                                    led.set_low();
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

                    // Count quick successive presses (releases)
                    let now = Instant::now();
                    recent_presses.push_back(now);
                    // drop anything older than the time window
                    while let Some(&t0) = recent_presses.front() {
                        if now.duration_since(t0) > MULTI_PRESS_WINDOW {
                            recent_presses.pop_front();
                        } else {
                            break;
                        }
                    }
                    if recent_presses.len() >= 7 {
                        println!("Button pressed 7 times quickly!");
                        recent_presses.clear();
                        thread::spawn(|| {
                            send_debug_logs_action();
                        });

                        // Blink for 5 seconds
                        let mut led = led_shared.lock().unwrap();
                        for _ in 0..10 {
                            led.set_high();
                            thread::sleep(Duration::from_millis(250));
                            led.set_low();
                            thread::sleep(Duration::from_millis(250));
                        }
                        drop(led);
                    }
                }
            }
            Ok(None) => {} // No event
            Err(e) => eprintln!("Error polling interrupt: {:?}", e),
        }
    }
}
