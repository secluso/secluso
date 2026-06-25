//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result, bail};
use rocket::{
    State, fairing::AdHoc, form::FromForm, fs::FileServer, get, http::ContentType, post,
    response::content::RawHtml, routes, serde::json::Json,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    cmp::Ordering,
    collections::VecDeque,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, RwLock, mpsc},
    thread,
    thread::JoinHandle,
    time::Duration,
};
use tokio::runtime::Builder as RtBuilder;
use walkdir::WalkDir;

// Types returned to UI
#[derive(Debug, Clone, Serialize)]
struct FrontEvent {
    f: usize,    // global frame index (legacy)
    txt: String, // human text
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>, // optional stage/label
    #[serde(skip_serializing_if = "Option::is_none")]
    ts: Option<u128>, // optional timestamp
}

// Normalizes a UUID-like string into the standard lowercase dashed format.
fn canon_uuid_like(s: &str) -> String {
    let t = s
        .trim()
        .trim_matches(|c| c == '{' || c == '}')
        .to_lowercase();
    // already dashed UUID?
    if t.len() == 36
        && t.as_bytes().get(8) == Some(&b'-')
        && t.as_bytes().get(13) == Some(&b'-')
        && t.as_bytes().get(18) == Some(&b'-')
        && t.as_bytes().get(23) == Some(&b'-')
        && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return t;
    }
    // 32 hex (no dashes) -> dashify
    if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return format!(
            "{}-{}-{}-{}-{}",
            &t[0..8],
            &t[8..12],
            &t[12..16],
            &t[16..20],
            &t[20..32]
        );
    }
    // otherwise keep as-is (lowercased)
    t
}

fn run_key_from_json(v: &Value) -> Option<String> {
    // direct string
    if let Some(s) = v.get("run_id").and_then(|x| x.as_str()) {
        let k = canon_uuid_like(s);
        if !k.is_empty() {
            return Some(k);
        }
    }
    // object (RunId struct)
    if let Some(obj) = v.get("run_id").and_then(|x| x.as_object()) {
        for k in [
            "uuid", "id", "short", "value", "Short", "Id", "UUID", "Value", "short_id", "ShortId",
        ] {
            if let Some(s) = obj.get(k).and_then(|x| x.as_str()) {
                let kk = canon_uuid_like(s);
                if !kk.is_empty() {
                    return Some(kk);
                }
            }
        }
        // fallback: stringify whole object
        let kk = canon_uuid_like(&v.get("run_id").unwrap().to_string());
        if !kk.is_empty() {
            return Some(kk);
        }
    }
    None
}

const COCO_LABELS: [&str; 80] = [
    "person",
    "bicycle",
    "car",
    "motorcycle",
    "airplane",
    "bus",
    "train",
    "truck",
    "boat",
    "traffic light",
    "fire hydrant",
    "stop sign",
    "parking meter",
    "bench",
    "bird",
    "cat",
    "dog",
    "horse",
    "sheep",
    "cow",
    "elephant",
    "bear",
    "zebra",
    "giraffe",
    "backpack",
    "umbrella",
    "handbag",
    "tie",
    "suitcase",
    "frisbee",
    "skis",
    "snowboard",
    "sports ball",
    "kite",
    "baseball bat",
    "baseball glove",
    "skateboard",
    "surfboard",
    "tennis racket",
    "bottle",
    "wine glass",
    "cup",
    "fork",
    "knife",
    "spoon",
    "bowl",
    "banana",
    "apple",
    "sandwich",
    "orange",
    "broccoli",
    "carrot",
    "hot dog",
    "pizza",
    "donut",
    "cake",
    "chair",
    "couch",
    "potted plant",
    "bed",
    "dining table",
    "toilet",
    "tv",
    "laptop",
    "mouse",
    "remote",
    "keyboard",
    "cell phone",
    "microwave",
    "oven",
    "toaster",
    "sink",
    "refrigerator",
    "book",
    "clock",
    "vase",
    "scissors",
    "teddy bear",
    "hair drier",
    "toothbrush",
];

fn coco_label_name(label: i32) -> &'static str {
    if label >= 0 && (label as usize) < COCO_LABELS.len() {
        COCO_LABELS[label as usize]
    } else {
        "unknown"
    }
}

fn is_noop_intent(v: &serde_json::Value) -> bool {
    if let Some(s) = v.get("intent").and_then(|x| x.as_str()) {
        let s = s.to_ascii_lowercase();
        return s == "noop" || s == "intent::noop" || s == "no_op" || s == "no-op";
    }
    if let Some(obj) = v.get("intent").and_then(|x| x.as_object()) {
        if obj.contains_key("NoOp") {
            return true;
        }
        if obj
            .get("type")
            .and_then(|t| t.as_str())
            .map(|t| t.eq_ignore_ascii_case("noop"))
            .unwrap_or(false)
        {
            return true;
        }
        if obj
            .get("kind")
            .and_then(|t| t.as_str())
            .map(|t| t.eq_ignore_ascii_case("noop"))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Serialize)]
struct SessionSummary {
    /// Session folder name under RUNS_ROOT.
    id: String,
}

#[derive(Debug, Clone, Serialize)]
struct SessionDetail {
    /// Session folder name under RUNS_ROOT.
    id: String,
    /// Browser URLs for frames (/runs/<id>/<subdir>/<file>).
    frames: Vec<String>,
    /// Per-frame events (mapped via stage.replay_frame_idx heuristic).
    events: Vec<FrontEvent>,
    /// Total frames available on disk (before tailing).
    frame_total: usize,
    /// Total events available in telemetry (before tailing).
    event_total: usize,
}

#[derive(Debug, Clone, Serialize)]
struct SessionPage {
    total: usize,
    offset: usize,
    limit: usize,
    sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct SeriesHealth {
    ts: u128,
    cpu: f32,
    ram: f32,
    temp: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SeriesTick {
    ts: u128,
    queue: usize,
    max_queue: usize,
    standby: bool,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct SeriesData {
    health: Vec<SeriesHealth>,
    ticks: Vec<SeriesTick>,
}

/// Shared App State
#[derive(Clone)]
struct AppState {
    runs_root: PathBuf,
    static_dir: PathBuf,
    session_ids: Arc<RwLock<Vec<String>>>,
}

#[derive(Debug, Default, FromForm)]
struct SessionQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    frames_tail: Option<usize>,
    events_tail: Option<usize>,
}

#[derive(Debug, Default, FromForm)]
struct SeriesQuery {
    tail: Option<usize>,
}

const DEFAULT_SESSION_LIMIT: usize = 20;
const MAX_SESSION_LIMIT: usize = 100;
const DEFAULT_FRAMES_TAIL: usize = 200;
const MAX_FRAMES_TAIL: usize = 5000;
const DEFAULT_EVENTS_TAIL: usize = 1000;
const MAX_EVENTS_TAIL: usize = 20000;
const DEFAULT_SERIES_TAIL: usize = 1500;
const MAX_SERIES_TAIL: usize = 20000;

/** Public API functions below **/
/// Spawn the Rocket server on a background thread.
pub fn spawn_replay_server(runs_root: impl Into<PathBuf>) -> (JoinHandle<Result<()>>, bool) {
    let runs_root: PathBuf = runs_root.into();

    // Used to notify the caller whether the server started successfully.
    let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), String>>();

    let handle = thread::Builder::new()
        .name("replay-rocket".into())
        .spawn(move || -> Result<()> {
            let rt = RtBuilder::new_multi_thread()
                .enable_all()
                .build()
                .context("building tokio runtime for replay server")?;

            rt.block_on(async move {
                // ---- Config (address/port via figment custom) ----
                let addr = std::env::var("REPLAY_ADDR").unwrap_or_else(|_| "0.0.0.0".into());
                let port: u16 = std::env::var("REPLAY_PORT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(8080);

                let static_dir =
                    PathBuf::from(std::env::var("STATIC_DIR").unwrap_or_else(|_| "static".into()));

                // Ensure required static assets exist before continuing.
                for f in ["index.html", "styles.css", "ui.js"] {
                    let p = static_dir.join(f);
                    if let Err(e) = must_exist(&p) {
                        let _ = ready_tx.send(Err(format!("{e:#}")));
                        return Err(e);
                    }
                }

                if !runs_root.exists() {
                    eprintln!(
                        "RUNS_ROOT does not exist: {} (continuing with zero sessions)",
                        runs_root.display()
                    );
                }

                // Initial scan (session IDs only)
                let session_ids = match load_session_ids(&runs_root) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("initial session scan failed: {e:#}")));
                        return Err(e);
                    }
                };

                let state = AppState {
                    runs_root: runs_root.clone(),
                    static_dir: static_dir.clone(),
                    session_ids: Arc::new(RwLock::new(session_ids)),
                };

                // Build Rocket with custom figment (address/port)
                let figment = rocket::Config::figment()
                    .merge(("address", addr.as_str()))
                    .merge(("port", port));

                // Clone the sender so the fairing can signal liftoff.
                let liftoff_tx = ready_tx.clone();

                let rocket = rocket::custom(figment)
                    .manage(state)
                    .mount("/", routes![index_route, styles_route, app_js_route])
                    .mount(
                        "/",
                        routes![
                            get_sessions,
                            get_session_one,
                            get_session_series,
                            reload_sessions
                        ],
                    )
                    .mount("/runs", FileServer::from(runs_root))
                    .mount("/static", FileServer::from(static_dir))
                    // Send success signal after Rocket has launched.
                    .attach(AdHoc::on_liftoff("ready-signal", move |rocket| {
                        let liftoff_tx = liftoff_tx.clone();
                        Box::pin(async move {
                            let cfg = rocket.config();
                            let _ = liftoff_tx.send(Ok(()));
                            println!("Rocket: launched from http://{}:{}", cfg.address, cfg.port);
                        })
                    }));

                // On failure (e.g., port in use), notify the caller.
                if let Err(e) = rocket.launch().await {
                    let _ = ready_tx.send(Err(format!("Rocket launch error: {e}")));
                    return Err(anyhow::anyhow!(e));
                }

                Ok(())
            })
        })
        .expect("failed to spawn replay-rocket thread");

    // Wait for confirmation that the server is running or failed.
    let started_ok = match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => true,
        Ok(Err(msg)) => {
            eprintln!("replay server failed: {msg}");
            false
        }
        Err(_timeout) => {
            eprintln!("replay server startup not confirmed (timeout)");
            false
        }
    };

    (handle, started_ok)
}

/**  Routes start here **/
/// GET / to serve static/index.html strictly from disk
#[get("/")]
async fn index_route(
    state: &State<AppState>,
) -> std::result::Result<RawHtml<String>, (ContentType, String)> {
    let path = state.static_dir.join("index.html");
    fs::read_to_string(&path)
        .map(RawHtml)
        .map_err(|e| (ContentType::Plain, format!("index.html read error: {e}")))
}

/// GET /styles.css to serve static/styles.css strictly from disk
#[get("/styles.css")]
async fn styles_route(
    state: &State<AppState>,
) -> std::result::Result<(ContentType, String), (ContentType, String)> {
    let path = state.static_dir.join("styles.css");
    fs::read_to_string(&path)
        .map(|s| (ContentType::CSS, s))
        .map_err(|e| (ContentType::Plain, format!("styles.css read error: {e}")))
}

/// GET /app.js to stream your local static/ui.js (the UI fetches /sessions itself)
#[get("/app.js")]
async fn app_js_route(
    state: &State<AppState>,
) -> std::result::Result<(ContentType, String), (ContentType, String)> {
    let ui_js_path = state.static_dir.join("ui.js");
    fs::read_to_string(&ui_js_path)
        .map(|s| (ContentType::JavaScript, s))
        .map_err(|e| (ContentType::Plain, format!("ui.js read error: {e}")))
}

/// GET /sessions to list of sessions (summaries only)
#[get("/sessions?<q..>")]
async fn get_sessions(state: &State<AppState>, q: Option<SessionQuery>) -> Json<SessionPage> {
    let q = q.unwrap_or_default();
    let limit = q
        .limit
        .unwrap_or(DEFAULT_SESSION_LIMIT)
        .clamp(1, MAX_SESSION_LIMIT);
    let offset = q.offset.unwrap_or(0);

    let ids = state.session_ids.read().unwrap();
    let total = ids.len();
    let start = offset.min(total);
    let end = (start + limit).min(total);

    let sessions = ids[start..end]
        .iter()
        .map(|id| SessionSummary { id: id.clone() })
        .collect();

    Json(SessionPage {
        total,
        offset: start,
        limit,
        sessions,
    })
}

/// GET /sessions/<id> to single session (frames+events)
#[get("/sessions/<id>?<q..>")]
async fn get_session_one(
    id: String,
    state: &State<AppState>,
    q: Option<SessionQuery>,
) -> Option<Json<SessionDetail>> {
    let q = q.unwrap_or_default();
    let frames_tail = q
        .frames_tail
        .unwrap_or(DEFAULT_FRAMES_TAIL)
        .clamp(0, MAX_FRAMES_TAIL);
    let events_tail = q
        .events_tail
        .unwrap_or(DEFAULT_EVENTS_TAIL)
        .clamp(0, MAX_EVENTS_TAIL);

    load_session_detail(&state.runs_root, &id, frames_tail, events_tail)
        .ok()
        .map(Json)
}

/// GET /sessions/<id>/series to health[] & ticks[] from telemetry.log
#[get("/sessions/<id>/series?<q..>")]
async fn get_session_series(
    id: String,
    state: &State<AppState>,
    q: Option<SeriesQuery>,
) -> Json<SeriesData> {
    let q = q.unwrap_or_default();
    let tail = q
        .tail
        .unwrap_or(DEFAULT_SERIES_TAIL)
        .clamp(0, MAX_SERIES_TAIL);

    let path = state.runs_root.join(&id).join("telemetry.log");
    let series = if path.exists() {
        build_series_from_telemetry(&path, Some(tail)).unwrap_or_default()
    } else {
        SeriesData::default()
    };
    Json(series)
}

/// POST /reload to rescan RUNS_ROOT
#[post("/reload")]
async fn reload_sessions(
    state: &State<AppState>,
) -> std::result::Result<(ContentType, String), (ContentType, String)> {
    match load_session_ids(&state.runs_root) {
        Ok(new_sessions) => {
            *state.session_ids.write().unwrap() = new_sessions;
            Ok((ContentType::Plain, "reloaded".into()))
        }
        Err(e) => Err((ContentType::Plain, format!("reload failed: {e:#}"))),
    }
}

/** Helper functions below **/
fn must_exist(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("Missing required file: {}", path.display());
    }
    Ok(())
}

/// Discover sessions as folders under root. A session is valid if it has frames
/// under <run>/frames (or fallback <run>/images).
fn load_session_ids(root: &Path) -> Result<Vec<String>> {
    if !root.exists() {
        return Ok(vec![]);
    }

    let mut ids = vec![];

    for entry in fs::read_dir(root).with_context(|| format!("read_dir {}", root.display()))? {
        let entry = entry?;
        if !entry.metadata()?.is_dir() {
            continue;
        }
        let run_id = entry.file_name().to_string_lossy().to_string();
        let run_dir = entry.path();
        if !run_dir.join("frames").exists() && !run_dir.join("images").exists() {
            continue;
        }
        ids.push(run_id);
    }

    // newest-first by id (if id encodes a timestamp)
    ids.sort_by(|a, b| b.cmp(a));
    Ok(ids)
}

fn load_session_detail(
    root: &Path,
    run_id: &str,
    frames_tail: usize,
    events_tail: usize,
) -> Result<SessionDetail> {
    let run_dir = root.join(run_id);
    if !run_dir.exists() {
        bail!("session not found: {}", run_id);
    }

    let frames_dir = run_dir.join("frames");
    let images_dir = run_dir.join("images");
    let telemetry_path = run_dir.join("telemetry.log");

    let (mut frames, mut frame_total) =
        collect_frames(run_id, &frames_dir, "frames", Some(frames_tail));
    if frames.is_empty() {
        let (alt_frames, alt_total) =
            collect_frames(run_id, &images_dir, "images", Some(frames_tail));
        frames = alt_frames;
        frame_total = alt_total;
    }

    if frames.is_empty() {
        bail!("no frames found for session: {}", run_id);
    }

    let (events, event_total) = if telemetry_path.exists() {
        build_events_from_telemetry(&telemetry_path, Some(events_tail))
    } else {
        (vec![], 0)
    };

    Ok(SessionDetail {
        id: run_id.to_string(),
        frames,
        events,
        frame_total,
        event_total,
    })
}

use std::time::SystemTime;

/// Prefer creation time, fall back to modified time, else epoch.
fn file_time(p: &Path) -> SystemTime {
    match fs::metadata(p) {
        Ok(md) => md
            .created()
            .or_else(|_| md.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH),
        Err(_) => SystemTime::UNIX_EPOCH,
    }
}

// Collect image files and their timestamps from the given directory.
fn collect_frames(
    run_id: &str,
    dir: &Path,
    web_subdir: &str,
    tail: Option<usize>,
) -> (Vec<String>, usize) {
    if !dir.exists() {
        return (vec![], 0);
    }

    // Gather (path, timestamp)
    let mut files: Vec<(PathBuf, SystemTime)> = WalkDir::new(dir)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "png" | "jpg" | "jpeg"))
                .unwrap_or(false)
        })
        .map(|p| {
            let ts = file_time(&p);
            (p, ts)
        })
        .collect();

    // Sort files in chronological order by timestamp, then name.
    files.sort_by(|(pa, ta), (pb, tb)| ta.cmp(tb).then_with(|| file_name_cmp(pa, pb)));

    let total = files.len();
    let tail = tail.unwrap_or(total).min(total);
    let start = total.saturating_sub(tail);

    let frames = files
        .into_iter()
        .skip(start)
        .filter_map(|(p, _ts)| p.file_name().map(|os| os.to_string_lossy().to_string()))
        .map(|file| format!("/runs/{}/{}/{}", run_id, web_subdir, file))
        .collect();

    (frames, total)
}

fn file_name_cmp(a: &Path, b: &Path) -> Ordering {
    let sa = a.file_name().unwrap().to_string_lossy();
    let sb = b.file_name().unwrap().to_string_lossy();
    sa.cmp(&sb) // zero-padded names will sort numerically
}

/// Parse telemetry.log into a compact series for the chart & runtime box.
fn build_series_from_telemetry(path: &Path, tail: Option<usize>) -> Result<SeriesData> {
    let file =
        fs::File::open(path).with_context(|| format!("open telemetry log {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut health: VecDeque<SeriesHealth> = VecDeque::new();
    let mut ticks: VecDeque<SeriesTick> = VecDeque::new();
    let max = tail.unwrap_or(usize::MAX);

    let push_tail = |list: &mut VecDeque<SeriesHealth>, item: SeriesHealth| {
        if max == 0 {
            return;
        }
        if list.len() == max {
            list.pop_front();
        }
        list.push_back(item);
    };

    let push_tail_tick = |list: &mut VecDeque<SeriesTick>, item: SeriesTick| {
        if max == 0 {
            return;
        }
        if list.len() == max {
            list.pop_front();
        }
        list.push_back(item);
    };

    for line in reader.lines().map_while(Result::ok) {
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");

        match kind {
            "health" | "health_stats" => {
                if let (Some(ts), Some(cpu), Some(ram), Some(temp)) = (
                    as_u128_opt(&v, "ts"),
                    as_f32_any(&v, &["cpu_pct", "cpu", "cpu_percent"]),
                    as_f32_any(&v, &["ram_pct", "ram", "mem_pct", "mem"]),
                    as_f32_any(&v, &["temp_c", "temp", "temp_celsius"]),
                ) {
                    push_tail(
                        &mut health,
                        SeriesHealth {
                            ts,
                            cpu,
                            ram,
                            temp,
                            run: run_key_from_json(&v),
                        },
                    );
                }
            }
            "tick_stats" | "tick" => {
                let ts = as_u128_opt(&v, "ts");
                let q = as_usize_any(&v, &["event_queue_len", "queue_len", "queue"]);
                let mq =
                    as_usize_any(&v, &["max_event_queue_len", "max_queue_len", "max_queue"]).or(q);
                let shf = as_bool_any(&v, &["standby_has_frame", "standby"]).unwrap_or(false);
                let ahf = as_bool_any(&v, &["active_has_frame", "active"]).unwrap_or(false);
                if let (Some(ts), Some(q), Some(mq)) = (ts, q, mq) {
                    push_tail_tick(
                        &mut ticks,
                        SeriesTick {
                            ts,
                            queue: q,
                            max_queue: mq,
                            standby: shf,
                            active: ahf,
                            run: run_key_from_json(&v),
                        },
                    );
                }
            }
            _ => { /* ignore */ }
        }
    }

    // Ensure time series are ordered by timestamp.
    let mut health: Vec<SeriesHealth> = health.into_iter().collect();
    let mut ticks: Vec<SeriesTick> = ticks.into_iter().collect();

    if health.len() >= 2 && health.windows(2).any(|w| w[0].ts > w[1].ts) {
        health.sort_by_key(|h| h.ts);
    }
    if ticks.len() >= 2 && ticks.windows(2).any(|w| w[0].ts > w[1].ts) {
        ticks.sort_by_key(|t| t.ts);
    }

    Ok(SeriesData { health, ticks })
}

/// Build per-frame events from telemetry.log.
/// Heuristic: remember the last replay_frame_idx from "stage" rows and attach subsequent events to that frame.
fn build_events_from_telemetry(path: &Path, tail: Option<usize>) -> (Vec<FrontEvent>, usize) {
    use std::collections::HashMap;

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error; cannot open telemetry.log {}: {e}", path.display());
            return (vec![], 0);
        }
    };
    let reader = BufReader::new(file);

    let mut events: VecDeque<FrontEvent> = VecDeque::new();
    let max = tail.unwrap_or(usize::MAX);
    let mut total_events = 0usize;
    let mut skipped_no_run = 0usize;

    // Anchor frame index per run (not used — always defaults to 0).
    let last_f_by_run: HashMap<String, usize> = HashMap::new();
    let default_f = 0usize;

    for line in reader.lines().map_while(Result::ok) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or("");

        // Require a concrete run key
        let run_key = match run_key_from_json(&v) {
            Some(k) if !k.is_empty() => k,
            _ => {
                skipped_no_run += 1;
                continue;
            }
        };

        // Shared metadata used by most event types.
        let ts = v.get("ts").and_then(|x| x.as_u64()).map(|u| u as u128);
        let stage_label: Option<String> = v
            .get("frame_rel")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                v.get("stage_name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            });

        // Anchor frame index — required for frame mapping but defaulted to 0.
        let f_for_ev = *last_f_by_run.get(&run_key).unwrap_or(&default_f);

        let mut push_ev = |txt: String, stage_override: Option<String>| {
            total_events += 1;
            if max == 0 {
                return;
            }
            if events.len() == max {
                events.pop_front();
            }
            let stage = stage_override.or_else(|| stage_label.clone());
            events.push_back(FrontEvent {
                f: f_for_ev,
                txt,
                run: Some(run_key.clone()),
                stage,
                ts,
            });
        };

        match kind {
            "detection" => {
                let dets = v.get("detections").and_then(|x| x.as_u64()).unwrap_or(0);
                let txt = if let Some(ms) = v.get("latency_ms").and_then(|x| x.as_u64()) {
                    format!("InferenceCompleted: {} detections ({} ms)", dets, ms)
                } else {
                    format!("InferenceCompleted: {} detections", dets)
                };
                push_ev(txt, None);
            }
            "fsm_transition" => {
                let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("?");
                let to = v.get("to").and_then(|x| x.as_str()).unwrap_or("?");
                push_ev(format!("{} ➜ {}", from, to), None);
            }
            "dropped_frame" => {
                let reason = v
                    .get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown");
                push_ev(format!("Dropped: {}", reason), None);
            }
            "inference_skipped" => {
                let reason = v
                    .get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("unknown");
                push_ev(format!("InferenceSkipped: {}", reason), None);
            }
            "stage_duration" => {
                if let Some(ms) = v.get("duration_ms").and_then(|x| x.as_u64())
                    && ms > 50
                    && let (Some(name), Some(kind2)) = (
                        v.get("stage_name").and_then(|s| s.as_str()),
                        v.get("stage_kind").and_then(|s| s.as_str()),
                    )
                {
                    push_ev(format!("{}:{} took {} ms", kind2, name, ms), None);
                }
            }
            "state_duration" => {
                if let (Some(activity), Some(ms)) = (
                    v.get("state")
                        .and_then(|s| s.as_str())
                        .or_else(|| v.get("activity").and_then(|s| s.as_str())),
                    v.get("duration_ms").and_then(|x| x.as_u64()),
                ) {
                    push_ev(format!("activity:{} took {} ms", activity, ms), None);
                }
            }
            "model_switch" => {
                let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("?");
                let to = v.get("to").and_then(|x| x.as_str()).unwrap_or("?");
                let reason = v.get("reason").and_then(|x| x.as_str()).unwrap_or("");
                let health = v.get("health").and_then(|x| x.as_str()).unwrap_or("");
                let mut s = format!("Model {} ➜ {}", from, to);
                if !reason.is_empty() {
                    s.push_str(&format!(" ({reason})"));
                }
                if !health.is_empty() {
                    s.push_str(&format!(" [{health}]"));
                }
                push_ev(s, None);
            }
            "motion_metrics" => {
                if let (Some(tp), Some(cp), Some(th), Some(w_b)) = (
                    v.get("total_points").and_then(|x| x.as_u64()),
                    v.get("clustered_points").and_then(|x| x.as_u64()),
                    v.get("threshold").and_then(|x| x.as_u64()),
                    v.get("w_b").and_then(|x| x.as_f64()),
                ) {
                    push_ev(
                        format!("Motion pts {}/{} thr {} w_b {}", cp, tp, th, w_b),
                        None,
                    );
                }
            }
            "detections_summary" => {
                if let Some(arr) = v.get("label_stats").and_then(|x| x.as_array()) {
                    let mut stats: Vec<(i32, usize, f32, f32)> = vec![];
                    for row in arr {
                        let Some(label) = row.get(0).and_then(|x| x.as_i64()) else {
                            continue;
                        };
                        let Some(count) = row.get(1).and_then(|x| x.as_u64()) else {
                            continue;
                        };
                        let avg = row.get(2).and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
                        let max = row.get(3).and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
                        stats.push((label as i32, count as usize, avg, max));
                    }
                    stats.sort_by(|a, b| {
                        b.1.cmp(&a.1)
                            .then_with(|| b.3.partial_cmp(&a.3).unwrap_or(Ordering::Equal))
                    });
                    let total: usize = stats.iter().map(|(_, count, _, _)| *count).sum();
                    let mut parts: Vec<String> = stats
                        .iter()
                        .take(5)
                        .map(|(label, count, avg, max)| {
                            let name = coco_label_name(*label);
                            format!("{name} x{count} (avg {avg:.2}, max {max:.2})")
                        })
                        .collect();
                    if stats.len() > 5 {
                        parts.push(format!("+{} more", stats.len() - 5));
                    }
                    if parts.is_empty() {
                        push_ev("Detections: none".to_string(), Some("detections".into()));
                    } else {
                        push_ev(
                            format!("Detections: {} (total {total})", parts.join("; ")),
                            Some("detections".into()),
                        );
                    }
                }
            }
            "intent_triggered" | "intent" => {
                if is_noop_intent(&v) {
                    continue;
                }
                let intent_str = v.get("intent").unwrap();
                push_ev(format!("Intent: {}", intent_str), None);
            }
            _ => { /* ignore */ }
        }
    }

    // Notify if we dropped events due to missing run_id
    if skipped_no_run > 0 {
        eprintln!(
            "build_events_from_telemetry: skipped {skipped_no_run} rows with no usable run_id"
        );
    }

    (events.into_iter().collect(), total_events)
}

/** JSON helpers below **/
fn as_u128_opt(v: &Value, key: &str) -> Option<u128> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .map(|u| u as u128)
        .or_else(|| {
            v.get(key)
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse::<u128>().ok())
        })
}

fn as_f32_opt(v: &Value, key: &str) -> Option<f32> {
    v.get(key)
        .and_then(|x| x.as_f64())
        .map(|f| f as f32)
        .or_else(|| {
            v.get(key)
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse::<f32>().ok())
        })
}

fn as_f32_any(v: &Value, keys: &[&str]) -> Option<f32> {
    for key in keys {
        if let Some(val) = as_f32_opt(v, key) {
            return Some(val);
        }
    }
    None
}

fn as_usize_opt(v: &Value, key: &str) -> Option<usize> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .map(|u| u as usize)
        .or_else(|| {
            v.get(key)
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse::<usize>().ok())
        })
}

fn as_usize_any(v: &Value, keys: &[&str]) -> Option<usize> {
    for key in keys {
        if let Some(val) = as_usize_opt(v, key) {
            return Some(val);
        }
    }
    None
}

fn as_bool_opt(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(|x| x.as_bool()).or_else(|| {
        v.get(key)
            .and_then(|x| x.as_str())
            .and_then(|s| match s.to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
    })
}

fn as_bool_any(v: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        if let Some(val) = as_bool_opt(v, key) {
            return Some(val);
        }
    }
    None
}
