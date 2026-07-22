//! Secluso IR cut filter toggler.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use embedded_hal::i2c::I2c;
use linux_embedded_hal::I2cdev;
use rppal::gpio::{Gpio, OutputPin};
use rppal::pwm::{Channel, Polarity, Pwm};
use std::{thread, time::Duration};

// ----------------- Shared I2C -----------------

const I2C_BUS: &str = "/dev/i2c-1";

// ----------------- TMP1075 (overtemp ALERT gating) -----------------

const TMP1075_ADDR_7BIT: u8 = 0x48;

// TMP1075 register pointers
const REG_TEMP: u8 = 0x00;
const REG_CONFIG: u8 = 0x01;
const REG_TLOW: u8 = 0x02;
const REG_THIGH: u8 = 0x03;

// CONFIG[15:8] = OS R1 R0 F1 F0 POL TM SD
// Comparator mode (TM=0), active-low (POL=0), continuous (SD=0), 1-fault (F1:F0=00)
const CONFIG_HIGH_BYTE: u8 = 0x00;

// Temp thresholds
const THIGH_C: f32 = 80.0;
const TLOW_C: f32 = 60.0;

// ----------------- TPS61161 PWM (IR LED enable/dim) -----------------

const PWM_FREQ_HZ: f64 = 10_000.0;
// Your working mapping:
const PWM_CHANNEL: Channel = Channel::Pwm1;

// GPIO13 is the hardware PWM pin used to drive TPS61161 CTRL through the AND gate
const GPIO13: u8 = 13;

// ----------------- IR/IR cut filter -----------------

const IN1_PIN: u8 = 17;      // BCM numbering
const IN2_PIN: u8 = 27;      // BCM numbering
const SLEEP_PIN: u8 = 4;     // 1=enable bridge, 0=disable bridge
const PULSE_MS: u64 = 120;

struct IrCut {
    in1: OutputPin,
    in2: OutputPin,
    sleep: OutputPin,
}

impl IrCut {
    fn new(gpio: &Gpio) -> anyhow::Result<Self> {
        let in1 = gpio.get(IN1_PIN)?.into_output_low();
        let in2 = gpio.get(IN2_PIN)?.into_output_low();
        let sleep = gpio.get(SLEEP_PIN)?.into_output_low();
        Ok(Self { in1, in2, sleep })
    }

    fn night(&mut self) {
        // Enable bridge driver IC
        self.in1.set_low();
        self.in2.set_low();
        self.sleep.set_high();
        thread::sleep(Duration::from_millis(1000));

        // Pulse coil: IN1=LOW, IN2=HIGH
        self.in1.set_low();
        self.in2.set_high();
        thread::sleep(Duration::from_millis(PULSE_MS));
        self.in1.set_low();
        self.in2.set_low();

        // Disable bridge driver IC
        self.sleep.set_low();

    }

    fn day(&mut self) {
        // Enable bridge driver IC
        self.in1.set_low();
        self.in2.set_low();
        self.sleep.set_high();
        thread::sleep(Duration::from_millis(1000));

        // Pulse coil: IN1=HIGH, IN2=LOW
        self.in1.set_high();
        self.in2.set_low();
        thread::sleep(Duration::from_millis(PULSE_MS));
        self.in1.set_low();
        self.in2.set_low();

        // Disable bridge driver IC
        self.sleep.set_low();
    }
}

// ----------------- Ambient light sensor -----------------

const AMBIENT_ADDR: u8 = 0x52;

// Register map (APDS-9306 / APDS-9306-065)
const REG_MAIN_CTRL: u8 = 0x00;      // ALS_EN is bit 1
//const REG_ALS_MEAS_RATE: u8 = 0x04;  // default 0x22
//const REG_ALS_GAIN: u8 = 0x05;       // default 0x01 (gain 3)
const REG_PART_ID: u8 = 0x06;        // APDS-9306-065 default 0xB3
const REG_MAIN_STATUS: u8 = 0x07;    // ALS data status bit indicates new data
const REG_ALS_DATA_0: u8 = 0x0D;     // 0x0D..0x0F = 20-bit ALS result (LSB aligned)

fn als_write_u8<I: I2c>(i2c: &mut I, reg: u8, val: u8) -> core::result::Result<(), I::Error> {
    i2c.write(AMBIENT_ADDR, &[reg, val])
}

fn als_read_u8<I: I2c>(i2c: &mut I, reg: u8) -> core::result::Result<u8, I::Error> {
    let mut b = [0u8; 1];
    i2c.write_read(AMBIENT_ADDR, &[reg], &mut b)?;
    Ok(b[0])
}

fn read_als_20bit<I: I2c>(i2c: &mut I) -> core::result::Result<u32, I::Error> {
    // Block read 3 bytes starting at 0x0D to keep bytes from the same conversion.
    let mut b = [0u8; 3];
    i2c.write_read(AMBIENT_ADDR, &[REG_ALS_DATA_0], &mut b)?;

    let raw = (b[0] as u32) | ((b[1] as u32) << 8) | (((b[2] as u32) & 0x0F) << 16);
    Ok(raw)
}

// ----------------- Main -----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Day,
    Night,
}

const LIGHT_THRESHOLD: u32 = 20;
const REQUIRED_CONSECUTIVE: u8 = 3;

fn main() -> Result<()> {
    // --- Init GPIO + IR Cut ---
    let gpio = Gpio::new()?;

    // Start in DAY mode: IR disabled initially.
    let mut ircut = IrCut::new(&gpio)?;
    let mut mode = Mode::Day;
    ircut.day();

    // Keep PWM handle here; Some(pwm) means IR LEDs ON.
    let mut ir_led_pwm: Option<Pwm> = None;

    // --- Init I2C bus & sensors ---
    let mut i2c = I2cdev::new(I2C_BUS)?;

    // Configure TMP1075 ALERT gating
    configure_tmp1075_alert(&mut i2c).context("configure TMP1075")?;

    // Read temperature once
    if let Ok(t) = read_temp_c(&mut i2c, TMP1075_ADDR_7BIT) {
        eprintln!("TMP1075 temp: {:.3} °C", t);
    }

    // Sanity: read Part ID (APDS-9306-065 typically reads 0xB3)
    let part_id = als_read_u8(&mut i2c, REG_PART_ID)?;
    println!("ALS PART_ID: 0x{:02X}", part_id);

    // Optional: configure measurement rate / resolution + gain
    // als_write_u8(&mut i2c, REG_ALS_MEAS_RATE, 0x22)?; // default: 18-bit, 100ms
    // als_write_u8(&mut i2c, REG_ALS_GAIN, 0x01)?;      // default: gain 3

    // Enable ALS: set ALS_EN (bit 1) in MAIN_CTRL
    als_write_u8(&mut i2c, REG_MAIN_CTRL, 0x02)?;

    // Wait at least one integration cycle (default is ~100ms)
    thread::sleep(Duration::from_millis(150));

    // Counters for consecutive light readings
    let mut below_cnt: u8 = 0;
    let mut above_cnt: u8 = 0;
    // When we turn on IR, it adds an offset to the ambient light readings.
    let mut light_threshold_offset = 0;

    loop {
        // --- Read sensors ---
        let status = als_read_u8(&mut i2c, REG_MAIN_STATUS)?;
        let als = read_als_20bit(&mut i2c)?;

        // MAIN_STATUS bit 3 indicates "new data not yet read" (per datasheet).
        let new_data = (status & (1 << 3)) != 0;

        println!(
            "Mode={:?} MAIN_STATUS=0x{:02X} new_data={} ALS(raw20)={}, light_threshold_offset={}",
            mode, status, new_data, als, light_threshold_offset
        );

        // --- Light-based hysteresis counters ---
        if als < LIGHT_THRESHOLD + light_threshold_offset {
            below_cnt = below_cnt.saturating_add(1);
            above_cnt = 0;
        } else {
            above_cnt = above_cnt.saturating_add(1);
            below_cnt = 0;
        }

        // --- Mode switching logic ---
        match mode {
            Mode::Day => {
                // Switch to NIGHT only if:
                //  - dark for REQUIRED_CONSECUTIVE readings
                if below_cnt >= REQUIRED_CONSECUTIVE {
                    println!(
                        "Condition met for DAY -> NIGHT: ALS<{} for {} readings",
                        LIGHT_THRESHOLD, REQUIRED_CONSECUTIVE
                    );

                    // Switch IR-cut to night mode
                    ircut.night();

                    // Turn IR LEDs ON (enable PWM)
                    ir_led_pwm = Some(enable_ir_led_pwm()?);

                    mode = Mode::Night;
                    below_cnt = 0;
                    thread::sleep(Duration::from_millis(100));
                    light_threshold_offset = read_als_20bit(&mut i2c)?;
                    println!("light_threshold_offset set to {}", light_threshold_offset);
                }
            }
            Mode::Night => {
                // Switch to DAY if:
                //  - bright for REQUIRED_CONSECUTIVE readings
                if above_cnt >= REQUIRED_CONSECUTIVE {
                    println!(
                        "Condition met for NIGHT -> DAY: ALS>={} for {} readings",
                        LIGHT_THRESHOLD, REQUIRED_CONSECUTIVE
                    );

                    // Turn IR LEDs OFF
                    disable_ir_led_pwm(&mut ir_led_pwm)?;

                    // Switch IR-cut to day mode
                    ircut.day();

                    mode = Mode::Day;
                    above_cnt = 0;
                    light_threshold_offset = 0;
                }
            }
        }

        // Log temp
        if let Ok(t) = read_temp_c(&mut i2c, TMP1075_ADDR_7BIT) {
            eprintln!("TMP1075 temp: {:.3} °C", t);
        }

        // One full iteration per second
        thread::sleep(Duration::from_secs(1));
    }
}

// ----------------- TMP1075 helpers -----------------

fn configure_tmp1075_alert(i2c: &mut I2cdev) -> Result<()> {
    i2c_write(i2c, TMP1075_ADDR_7BIT, &[REG_CONFIG, CONFIG_HIGH_BYTE])
        .context("write TMP1075 config")?;

    let t_low_reg = tmp1075_thresh_reg_from_c(TLOW_C);
    let t_high_reg = tmp1075_thresh_reg_from_c(THIGH_C);

    write_u16_be(i2c, TMP1075_ADDR_7BIT, REG_TLOW, t_low_reg).context("write TLOW")?;
    write_u16_be(i2c, TMP1075_ADDR_7BIT, REG_THIGH, t_high_reg).context("write THIGH")?;

    Ok(())
}

fn i2c_write<I: I2c>(i2c: &mut I, addr: u8, bytes: &[u8]) -> Result<()> {
    i2c.write(addr, bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))
}

fn write_u16_be<I: I2c>(i2c: &mut I, addr: u8, reg: u8, val: u16) -> Result<()> {
    let msb = ((val >> 8) & 0xFF) as u8;
    let lsb = (val & 0xFF) as u8;
    i2c_write(i2c, addr, &[reg, msb, lsb])
}

fn read_temp_c<I: I2c>(i2c: &mut I, addr: u8) -> Result<f32> {
    let mut buf = [0u8; 2];
    i2c.write_read(addr, &[REG_TEMP], &mut buf)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let raw = u16::from_be_bytes(buf);
    let t12 = (raw >> 4) as i16;
    let signed = if (t12 & 0x0800) != 0 { t12 | !0x0FFF } else { t12 };
    Ok((signed as f32) * 0.0625)
}

fn tmp1075_thresh_reg_from_c(temp_c: f32) -> u16 {
    let raw = (temp_c * 16.0).round() as i16; // 0.0625°C => *16
    (raw as u16) << 4
}

// ----------------- IR LED PWM helpers -----------------

fn enable_ir_led_pwm() -> Result<Pwm> {
    let pwm = Pwm::with_frequency(PWM_CHANNEL, PWM_FREQ_HZ, 1.0, Polarity::Normal, true)
        .context("enable PWM on GPIO13")?;
    eprintln!("IR LEDs ON (PWM {} Hz, 100% duty)", PWM_FREQ_HZ);
    Ok(pwm)
}

fn disable_ir_led_pwm(ir_led_pwm: &mut Option<Pwm>) -> Result<()> {
    *ir_led_pwm = None;
    ir_led_off()?;
    eprintln!("IR LEDs OFF");
    Ok(())
}

// Force CTRL low long enough to ensure TPS61161 enters shutdown (>2.5ms low)
fn ir_led_off() -> Result<()> {
    let gpio = Gpio::new().context("open GPIO for IR off")?;
    let mut pin = gpio.get(GPIO13).context("get GPIO13")?.into_output_low();
    thread::sleep(Duration::from_millis(3));
    pin.set_low();
    Ok(())
}
