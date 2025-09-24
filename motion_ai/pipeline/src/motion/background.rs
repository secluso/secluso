use crate::frame::RawFrame;
use crate::logic::pipeline::RunId;
use crate::motion;
use image::GrayImage;
use ndarray::{Array2, Zip};

#[derive(Clone)]
pub struct BackgroundSubtractor {
    background: Array2<f32>,
    width: u32,
    height: u32,
}

/// Developed to not detect motion in gradual changes over time such as the sun going up and down throughout the day.
/// Such that, it creates a standardized 'background' that's updated gradually over time based on input frames.
impl BackgroundSubtractor {
    /// Initialize with the first frame
    pub fn new(initial_frame: &GrayImage) -> Self {
        let (width, height) = initial_frame.dimensions();
        let bg_vec: Vec<f32> = initial_frame.as_raw().iter().map(|&p| p as f32).collect();

        let bg = Array2::from_shape_vec((height as usize, width as usize), bg_vec)
            .expect("Failed to create ndarray from initial frame");

        BackgroundSubtractor {
            background: bg,
            width,
            height,
        }
    }

    pub fn save_backed_image(
        &mut self,
        session_id: &str,
        run_id: &RunId,
    ) -> Result<(), anyhow::Error> {
        let image_data: Vec<u8> = self
            .background
            .iter()
            .map(|&val| val.clamp(0.0, 255.0).round() as u8)
            .collect();
        let image = GrayImage::from_raw(self.width, self.height, image_data)
            .expect("Failed to create GrayImage from mask");

        RawFrame::save_gray_image(&image, session_id, run_id, "background_data")?;

        Ok(())
    }

    /// Update background model and detect motion
    /// Updated from IP motion detection to be parallelized for faster run time and high efficiency
    pub fn apply(&mut self, frame: &GrayImage, adjusted_alpha: f32, night: bool) -> GrayImage {
        let (width, height) = frame.dimensions();

        // Convert GrayImage pixels to f32 and form a ndarray.
        let frame_vec: Vec<f32> = frame.as_raw().iter().map(|&p| p as f32).collect();
        let frame_array = Array2::from_shape_vec((height as usize, width as usize), frame_vec)
            .expect("Failed to create ndarray from frame");

        // Compute the difference in parallel using Zip:
        // diff = abs(frame_array - background)
        let mut diff = frame_array.clone();
        Zip::from(&mut diff)
            .and(&self.background)
            .par_for_each(|d, &bg| {
                *d = (*d - bg).abs();
            });

        // Update the background in parallel:
        Zip::from(&mut self.background)
            .and(&frame_array)
            .par_for_each(|bg, &fa| {
                *bg = fa * adjusted_alpha + *bg * (1.0 - adjusted_alpha);
            });

        // Create a binary mask in parallel.
        // For each element in diff, if > THRESHOLD, set to 255, otherwise 0.
        let mask = diff.mapv(|v| {
            if (!night && v > motion::detector::DAY_THRESHOLD as f32)
                || (night && v > motion::detector::NIGHT_THRESHOLD as f32)
            {
                255
            } else {
                0
            }
        });
        let out_vec: (Vec<u8>, Option<usize>) = mask.into_raw_vec_and_offset();

        //todo: make use of offset

        GrayImage::from_raw(width, height, out_vec.0).expect("Failed to create GrayImage from mask")
    }
}
