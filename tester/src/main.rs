//! Tester to test the reliability of Secluso components.
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

use std::fs;
use std::io;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

mod fault_injection;
use crate::fault_injection::inject_faults;

const INJECT_FAULT_ENV_VAR: &str = "INJECT_FAULT";

#[derive(PartialEq, Debug)]
enum FaultComponent {
    Server,
    CameraHub,
    App,
}

#[derive(PartialEq, Debug)]
enum FaultType {
    Fault(String),
    None,
}

#[derive(PartialEq, Debug)]
enum TestType {
    Motion(FaultComponent, FaultType),
    Livestream(FaultComponent, FaultType),
}

fn compile_server() -> io::Result<()> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("cargo build")
        .current_dir("../server")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    child.wait()?;
    Ok(())
}

fn compile_camera_hub() -> io::Result<()> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("cargo build --features ip")
        .current_dir("../camera_hub")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    child.wait()?;
    Ok(())
}

fn compile_app() -> io::Result<()> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("cargo build --example app --features for-example")
        .current_dir("../android_app_native")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    child.wait()?;
    Ok(())
}

fn compile_all() -> io::Result<()> {
    compile_server()?;
    compile_camera_hub()?;
    compile_app()?;

    Ok(())
}

fn spawn_server(test_type: &TestType) -> io::Result<Child> {
    let (arg, fault_tag) = parse_test_type(test_type, FaultComponent::Server)?;

    Command::new("../../../server/target/debug/secluso-server")
        .arg(arg)
        .current_dir("./data/server")
        .env(INJECT_FAULT_ENV_VAR, fault_tag)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
}

fn spawn_camera_hub(test_type: &TestType) -> io::Result<Child> {
    let (arg, fault_tag) = parse_test_type(test_type, FaultComponent::CameraHub)?;

    Command::new("../../../camera_hub/target/debug/secluso-camera-hub")
        .arg(arg)
        .current_dir("./data/camera_hub")
        .env(INJECT_FAULT_ENV_VAR, fault_tag)
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

fn spawn_app(test_type: &TestType) -> io::Result<Child> {
    let (arg, fault_tag) = parse_test_type(test_type, FaultComponent::App)?;

    Command::new("../../../android_app_native/target/debug/examples/app")
        .arg(arg)
        .current_dir("./data/app")
        .env(INJECT_FAULT_ENV_VAR, fault_tag)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}

fn get_fault_tag<'a>(
    fault_type: &'a FaultType,
    fault_component: &FaultComponent,
    asking_component: &FaultComponent,
) -> &'a str {
    if *asking_component != *fault_component {
        ""
    } else if let FaultType::Fault(t) = fault_type {
        t
    } else {
        ""
    }
}

fn parse_test_type(
    test_type: &TestType,
    asking_component: FaultComponent,
) -> io::Result<(String, String)> {
    if let TestType::Motion(fault_component, fault_type) = test_type {
        let tag = get_fault_tag(fault_type, fault_component, &asking_component);
        return Ok(("--test-motion".to_string(), tag.to_string()));
    } else if let TestType::Livestream(fault_component, fault_type) = test_type {
        let tag = get_fault_tag(fault_type, fault_component, &asking_component);
        return Ok(("--test-livestream".to_string(), tag.to_string()));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Error: Invalid test type {:?}!", test_type),
    ))
}

fn file_exists(path_str: &str) -> io::Result<()> {
    let path = Path::new(path_str);

    if !path.exists() {
        return Err(io::Error::other(format!(
            "Error: could not find {path_str}!"
        )));
    }

    Ok(())
}

fn prepare_environment() -> io::Result<()> {
    file_exists("user_credentials")?;
    file_exists("cameras.yaml")?;
    file_exists("camera_secret")?;

    let _ = fs::remove_dir_all("./data");

    fs::create_dir_all("./data/server/user_credentials")?;
    fs::copy(
        "user_credentials",
        "./data/server/user_credentials/user_credentials",
    )?;

    fs::create_dir_all("./data/camera_hub")?;
    fs::copy("user_credentials", "./data/camera_hub/user_credentials")?;
    fs::copy("cameras.yaml", "./data/camera_hub/cameras.yaml")?;
    fs::copy("camera_secret", "./data/camera_hub/camera_secret")?;

    fs::create_dir_all("./data/app")?;
    fs::copy("user_credentials", "./data/app/user_credentials")?;
    fs::copy("camera_secret", "./data/app/camera_secret")?;

    Ok(())
}

/// A test session involves launching the three compoents and getting them
/// to interact either for motion or livestream video.
/// A session might also involves fault injection.
fn run_test_session(test_type: TestType, clean_environment: bool) -> io::Result<i32> {
    if clean_environment {
        println!("Preparing environment (needed directories and files)");
        prepare_environment()?;
    } else {
        println!("Reusing environment (needed directories and files)");
        file_exists("data")?;
    }

    println!("Starting server...");
    let mut server = spawn_server(&test_type)?;

    thread::sleep(Duration::from_secs(1));

    println!("Starting camera hub...");
    let mut camera_hub = spawn_camera_hub(&test_type)?;

    thread::sleep(Duration::from_secs(3));

    println!("Starting app...");
    let mut app = spawn_app(&test_type)?;

    println!("Waiting for app to finish...");
    let app_exit_status = app.wait()?;

    let app_exit_code = app_exit_status.code().unwrap_or_default();

    println!("App finished. Killing camera_hub and server...");

    camera_hub.kill()?;
    camera_hub.wait()?;

    server.kill()?;
    server.wait()?;

    println!("Test complete!");

    Ok(app_exit_code)
}

fn main() -> io::Result<()> {
    let target_file = "../camera_hub/src/main.rs";
    let _ = fs::copy(target_file, "original");
    let num_injected_faults = inject_faults(target_file)?;

    compile_all()?;

    // Construct tests for all the injected faults.
    let mut tests = vec![];
    for i in 0..num_injected_faults {
        tests.push((
            TestType::Motion(
                FaultComponent::CameraHub,
                FaultType::Fault(format!("fault_tag_{}", i)),
            ),
            TestType::Motion(FaultComponent::CameraHub, FaultType::None),
        ));
        tests.push((
            TestType::Livestream(
                FaultComponent::CameraHub,
                FaultType::Fault(format!("fault_tag_{}", i)),
            ),
            TestType::Livestream(FaultComponent::CameraHub, FaultType::None),
        ));
    }

    for test in tests {
        println!("*********************************************");
        println!("Running test: {:?}", test);
        println!("*********************************************");
        let _ = run_test_session(test.0, true);
        let ret = run_test_session(test.1, false);
        if let Ok(app_exit_code) = ret {
            if app_exit_code != 0 {
                println!("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
                println!("Test succeeded in corrupting the system!");
                println!("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
            }
        }
    }

    let _ = fs::copy("original", target_file);

    Ok(())
}
