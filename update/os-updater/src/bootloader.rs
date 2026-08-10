//! SPDX-License-Identifier: GPL-3.0-or-later

/// We use the bootloader backend to maintain the A/B slots.
/// This is the backend for  Raspberry Pi: <https://github.com/Rtone/raspberrypi-firmware-rauc-bootloader-backend/blob/c8aa8ab78f9eb12c42d5b45f7d27c430bce8b7ef/bootloader-custom-backend>
/// It uses the tryboot Raspberry Pi feature to ensure atomic fail-safe OS updates <https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#fail-safe-os-updates-tryboot>
/// Based on the <https://rauc.readthedocs.io/en/latest/integration.html#custom-bootloader-backend-interface> format
use anyhow::{Context, anyhow};
use std::process::Command;

// Location for the backend as described in the header comment.
const BOOTLOADER_BACKEND: &str = "/usr/sbin/bootloader-backend";

/**
    In addition to the primary slot, RAUC must also be able to determine the boot state of a specific slot.
    RAUC determines the necessary boot state by calling the custom bootloader handler with the argument get-state <slot.bootname>.
    Whereupon the handler has to output the state good or bad to stdout and exit with the return value 0.
    If the state cannot be determined or another error occurs, the custom bootloader handler must exit with non-zero return value.
*/
#[allow(dead_code)]
fn get_state() -> anyhow::Result<String> {
    run_command("get-state", vec![])
}

/**
    To set the boot state to the desire slot, the handler is called with argument set-state <slot.bootname> <state>.
    As already mentioned in the paragraph above, the <slot.bootname> matches the bootname= key defined for the respective slot in your system.conf.
    The <state> argument corresponds to one of the following values:

    good if the last start of the slot was successful or
    bad if the last start of the slot failed.

    The return value must be 0 if the boot state was set successfully, or non-zero if an error occurred.
*/
#[allow(dead_code)]
fn set_state(state: &str) -> anyhow::Result<()> {
    let _ = run_command("set-primary", vec![state])?;
    Ok(())
}

/**
    To get the primary slot, the handler is called with the argument get-primary.
    The handler must output the current primary slot’s bootname on the stdout, and return 0 on exit, if no error occurred.
    In case of failure, the handler must return with non-zero value.
*/
pub(crate) fn get_primary() -> anyhow::Result<i32> {
    let stdout = run_command("get-primary", vec![])?;

    stdout
        .parse()
        .context("Failed to parse String into Integer")
}

/**
    Accordingly, in order to set the primary slot, the custom bootloader handler is called with argument set-primary <slot.bootname>
    where <slot.bootname> matches the bootname= key defined for the respective slot in your system.conf.
    If the set was successful, the handler must also return with a 0, otherwise the return value must be non-zero.
*/
pub(crate) fn set_primary(slot_bootname: &str) -> anyhow::Result<()> {
    let _ = run_command("set-primary", vec![slot_bootname])?;
    Ok(())
}

/**
    To get the current running slot, the handler must be called with the argument get-current.
    The handler must output the current running slot’s bootname on the stdout, and return 0 on exit, if no error occurred.
    Implementing this is only needed when the /proc/cmdline is not providing information about current booted slot.
*/
#[allow(dead_code)]
pub(crate) fn get_current() -> anyhow::Result<i32> {
    let stdout = run_command("get-current", vec![])?;

    stdout
        .parse()
        .context("Failed to parse String into Integer")
}

/// Utility function to run a command and follow the standard protocol.
/// Is success? Return stdout.
/// Is error? Return error.
fn run_command(command: &str, additional_args: Vec<&str>) -> anyhow::Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(BOOTLOADER_BACKEND)
        .arg(command)
        .args(additional_args)
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let status = output.status;

    if status.success() {
        Ok(stdout)
    } else {
        Err(anyhow!(stderr))
    }
}
