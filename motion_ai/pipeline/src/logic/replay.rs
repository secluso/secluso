use crate::frame::RawFrame;
use crate::logic::intent::Intent;
use crate::logic::pipeline::PipelineEvent;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Timestamped wrapper for any recorded item (frame, event, or intent).
#[derive(Serialize, serde::Deserialize)]
pub struct ReplayEntry<T> {
    pub when: SystemTime,
    pub item: T,
}

/// Stores a timeline of frames, events, and intents for later analysis or replay.
#[derive(Serialize, Deserialize, Default)]
pub struct ReplayRecorder {
    pub frames: Vec<ReplayEntry<RawFrame>>,
    pub events: Vec<ReplayEntry<PipelineEvent>>,
    pub intents: Vec<ReplayEntry<Intent>>,
}

/// Records a frame with the current timestamp into the replay log.
impl ReplayRecorder {
    /// Records a frame with the current timestamp into the replay log.
    pub fn record_frame(&mut self, frame: &RawFrame) {
        self.frames.push(ReplayEntry {
            when: SystemTime::now(),
            item: frame.clone(),
        });
    }

    /// Records a pipeline event into the event timeline.
    pub fn record_event(&mut self, ev: &PipelineEvent) {
        self.events.push(ReplayEntry {
            when: SystemTime::now(),
            item: ev.clone(),
        });
    }

    /// Records an intent that was executed during the pipeline run.
    pub fn record_intent(&mut self, intent: &Intent) {
        self.intents.push(ReplayEntry {
            when: SystemTime::now(),
            item: intent.clone(),
        });
    }

    /// Saves the recorded replay data to a JSON file at the specified path.
    #[allow(dead_code)]
    pub fn save_to<P: AsRef<std::path::Path>>(&self, path: P) -> std::io::Result<()> {
        let f = std::fs::File::create(path)?;
        serde_json::to_writer(f, &self)?;
        Ok(())
    }

    /// Loads replay data from a JSON file into a ReplayRecorder.
    #[allow(dead_code)]
    pub fn load_from<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Self> {
        let f = std::fs::File::open(path)?;
        Ok(serde_json::from_reader(f)?)
    }
}
