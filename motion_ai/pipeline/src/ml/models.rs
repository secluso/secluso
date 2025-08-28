use crate::frame::RawFrame;
use crate::logic::pipeline::RunId;
use crate::logic::telemetry::TelemetryRun;
use crate::ml::nanodet::NanodetRunner;
use once_cell::sync::Lazy;
use ort::session::Session;
use ort::session::builder::SessionBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use thiserror::Error;
use include_dir::{Dir, include_dir};

/// Lazily-initialized map of model kinds to file paths, loaded from config.
static MODEL_PATHS: OnceLock<HashMap<ModelKind, String>> = OnceLock::new();

/// Thread-safe global cache of ONNX sessions per model kind.
static SESSION_CACHE: Lazy<Mutex<HashMap<ModelKind, SessionEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Loads the models.toml configuration into the binary when compiling
static MODEL_CONFIG: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/models.toml"));

/// Loads the model ONNX files directory into the binary when compiling
static MODEL_DATA_DIR: Dir<'_>  = include_dir!("$CARGO_MANIFEST_DIR/onnx_models");

/// Associates an ONNX session with the model path it was built from, to detect changes.
struct SessionEntry {
    path: String,
    session: Session,
}

/// Extension for hash map entries that allows fallible insertion (Result-returning version of `or_insert_with`).
trait EntryExt<'a, K, V> {
    fn or_try_insert_with<E, F>(self, f: F) -> Result<&'a mut V, E>
    where
        F: FnOnce() -> Result<V, E>;
}

impl<'a, K, V> EntryExt<'a, K, V> for std::collections::hash_map::Entry<'a, K, V>
where
    K: Eq + std::hash::Hash,
{
    fn or_try_insert_with<E, F>(self, f: F) -> Result<&'a mut V, E>
    where
        F: FnOnce() -> Result<V, E>,
    {
        match self {
            std::collections::hash_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let value = f()?;
                Ok(entry.insert(value))
            }
        }
    }
}

/// Provides access to a cached ONNX `Session` for a given model type.
/// Rebuilds the session if the model path has changed.
pub fn with_session<F, R>(kind: &ModelKind, f: F) -> Result<R, ModelError>
where
    F: FnOnce(&mut Session) -> R,
{
    let paths = MODEL_PATHS
        .get()
        .ok_or_else(|| ModelError::Inference("init_model_paths not called".into()))?;
    let mut cache = SESSION_CACHE
        .lock()
        .map_err(|_| ModelError::Inference("Mutex poisoned".into()))?;
    let wanted_path = paths
        .get(kind)
        .ok_or_else(|| ModelError::Inference(format!("No path for model kined: {:?}", kind)))?;

    // If we haven't made this yet or we changed the path, we'll go ahead and re-create it now.
    let entry = cache.entry(kind.clone()).or_try_insert_with(|| {
        let sess = build_session(wanted_path)?;
        Ok::<SessionEntry, ModelError>(SessionEntry {
            path: wanted_path.clone(),
            session: sess,
        })
    })?;

    if &entry.path != wanted_path {
        // hot swap because we changed the config
        entry.session = build_session(wanted_path)?;
        entry.path = wanted_path.clone();
    }

    let session = &mut entry.session;
    Ok(f(session))
}

/// Constructs a new ONNX session from the specified model path using default threading config.
fn build_session(path: &str) -> Result<Session, ort::Error> {
    Ok(SessionBuilder::new()?
        .with_inter_threads(1)?
        .with_intra_threads(1)?
        .commit_from_memory(MODEL_DATA_DIR.get_file(path).unwrap().contents())?)
}

/// Loads model file paths from `models.toml` and registers them for later lookup.
pub fn init_model_paths() -> Result<bool, ModelError> {
    let raw: toml::Value = toml::from_str(&MODEL_CONFIG)
        .map_err(|e| ModelError::Inference(format!("Failed to parse TOML: {}", e)))?;
    let tbl = raw["models"]
        .as_table()
        .ok_or_else(|| ModelError::Inference("Missing [models] table in TOML".into()))?;

    let fast_path = tbl
        .get("fast")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ModelError::Inference("Missing fast path in TOML".into()))?;
    let accurate_path = tbl
        .get("accurate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ModelError::Inference("Missing accurate path in TOML".into()))?;

    Ok(MODEL_PATHS
        .set(
            vec![
                (ModelKind::Fast, fast_path.to_string()),
                (ModelKind::Accurate, accurate_path.to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .is_ok()) // An error here is practically impossible, but we'll return whether it was successful in bool terms.
}

/// Represents the type of ML model to use: a fast, lightweight one or an accurate, heavier one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum ModelKind {
    Fast,
    Accurate,
}

/// Provides string representations of model kinds for telemetry/logging.
impl std::fmt::Display for ModelKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelKind::Fast => write!(f, "fast"),
            ModelKind::Accurate => write!(f, "accurate"),
        }
    }
}

/// Semantic label categories for detected objects in a frame.
#[derive(Eq, Hash, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum DetectionType {
    Human,
    Car,
    Animal,
    Other,
}

/// Trait for decoding model output into structured detection results.
/// Implemented by each supported model backend (e.g., NanoDet).
pub trait ModelRunner {
    fn decode(
        kind: &ModelKind,
        frame: &RawFrame,
        telemetry: &mut TelemetryRun,
        run_id: &RunId,
    ) -> Result<DetectionResult, ModelError>;
}

/// Error types for model inference, IO, ONNX runtime, or decoding logic.
#[derive(Error, Debug)]
pub enum ModelError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ORT error: {0}")]
    Ort(#[from] ort::Error),

    #[error("NDArray Error: {0}")]
    NdArray(#[from] ndarray::ShapeError),

    #[error("Inference error: {0}")]
    Inference(String),
}

/// Contains results from a single model inference run, including bounding boxes and timing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub(crate) runtime: Duration,
    pub(crate) results: Vec<BoxInfo>,
}

/// Represents a single bounding box and classification result from inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxInfo {
    pub(crate) x1: f32,
    pub(crate) y1: f32,
    pub(crate) x2: f32,
    pub(crate) y2: f32,
    pub(crate) score: f32,
    pub(crate) label: i32,
    pub(crate) det_type: DetectionType, // None = "Other, not relevant to us
    pub(crate) confidence: f32,
}

impl ModelKind {
    pub fn run(
        self,
        frame: &RawFrame,
        telemetry: &mut TelemetryRun,
        run_id: &RunId,
    ) -> Result<DetectionResult, ModelError> {
        NanodetRunner::decode(&self, frame, telemetry, run_id)
    }
}
