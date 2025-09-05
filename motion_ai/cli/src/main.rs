use std::io::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::path::PathBuf;

use secluso_motion_ai::backend::spawn_replay_server;
use secluso_motion_ai::logic::pipeline::PipelineController;
use secluso_motion_ai::frame::RawFrame;
use secluso_motion_ai::pipeline;

use video_rs::*;

/// Matches label for MacOS laptop CPU sensor (allows to test on Mac computer when Raspberry Pi is inaccessible)
#[cfg(not(feature = "raspberry"))]
const TEMP_LABEL: &str = "PMU tdie0";

/// Matches label for Broadcom internal temp sensor for CPU on Raspberry Pi Zero 2W & Raspberry Pi 4
#[cfg(feature = "raspberry")]
const TEMP_LABEL: &str = "cpu_thermal temp1";

fn main() -> anyhow::Result<()> {
    println!("Select mode:");
    println!("1. Telemetry mode (run web server)");
    println!("2. File mode (process an MP4 file)");
    print!("Enter choice (1 or 2): ");
    let _ = stdout().flush();

    let mut mode_input = String::new();
    stdin().read_line(&mut mode_input)?;
    let mode = mode_input.trim();

    match mode {
        "1" => {
            print!("Enter path to 'output/runs' directory (leave blank for default): ");
            let _ = stdout().flush();

            let mut runs_path_input = String::new();
            stdin().read_line(&mut runs_path_input)?;
            let runs_path_trimmed = runs_path_input.trim();
            let runs_root = if runs_path_trimmed.is_empty() {
                PathBuf::from("output/runs")
            } else {
                PathBuf::from(runs_path_trimmed)
            };

            let (_join_handle, success) = spawn_replay_server(runs_root);
            if !success {
                println!("Replay server failed to start.");
                return Ok(());
            }
            println!("Replay server running. Ctrl+C to exit.");
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        "2" => {
            // File mode
            print!("Enter MP4 file path: ");
            let _ = stdout().flush();

            let mut input = String::new();
            stdin().read_line(&mut input)?;
            let input_trimmed = input.trim_end();

            use_from_video(input_trimmed)?;
        }
        _ => {
            println!("Invalid selection. Exiting.");
        }
    }

    Ok(())
}

fn use_from_video(video_path: &str) -> std::result::Result<(), anyhow::Error> {
    video_rs::init().unwrap();

    // Build pipeline with motion and inference stages
    let pipeline = pipeline![
        secluso_motion_ai::logic::stages::MotionStage,
        secluso_motion_ai::logic::stages::InferenceStage,
    ];

    // Create and start controller
    let mut new_controller = PipelineController::new(pipeline, true)?;
    new_controller.start_working();
    let controller = Arc::new(Mutex::new(new_controller));
    let controller_clone = Arc::clone(&controller);

    // Background thread: runs the pipeline's main event loop
    thread::spawn(move || {
        //todo: only loop until exit
        loop {
            // when false (health issue), we should exit + we should also have some way for user to safely exit
            let result = controller_clone.lock().unwrap().tick(TEMP_LABEL);
            if let Err(e) = result {
                println!("Encountered error: {e}");
                break;
            } else if let Ok(accepted) = result {
                if !accepted {
                    println!("Not accepted");
                    break;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }

        println!("Exited loop");
    });

    let mut decoder = Decoder::new(Path::new(video_path)).expect("failed to create decoder");

    let mut frame_num = 1;
    let fps = 3;
    let mut last_frame_time: f32 = 0f32;
    for frame in decoder.decode_iter() {
        if let Ok((time, frame)) = frame {
            let min_diff = 1f32 / fps as f32;

            // Drop frames to approximate desired FPS
            if time.as_secs() >= last_frame_time + min_diff {
                last_frame_time = time.as_secs();

                let raw_frame = RawFrame::create_from_rgb(frame);
                controller.lock().unwrap().push_frame(raw_frame?);
            }
        } else {
            break; // Stop decoding on failure
        }

        frame_num = frame_num + 1;
    }

    Ok(())
}
