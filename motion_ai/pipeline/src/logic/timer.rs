use crate::logic::pipeline::PipelineEvent;
use std::sync::{LazyLock, LockResult, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Abstract interface for timer behavior used by the pipeline (start, cancel, poll).
pub trait Timer: Send + Sync {
    // Starts a countdown timer.
    fn start(&mut self, duration: Duration);

    // Cancels any active countdown.
    fn cancel(&mut self);

    // Checks if the timer has expired; returns a pipeline event if so.
    fn poll(&mut self) -> Option<PipelineEvent>;
}

/// Implements the Timer trait for TimerManager with basic countdown behavior.
impl Timer for TimerManager {
    fn start(&mut self, duration: Duration) {
        self.deadline = Some(Instant::now() + duration);
    }

    fn cancel(&mut self) {
        self.deadline = None;
    }

    fn poll(&mut self) -> Option<PipelineEvent> {
        TimerManager::poll(self)
    }
}

/// Default timer implementation that manages a single countdown deadline.
pub struct TimerManager {
    pub(crate) deadline: Option<Instant>,
}

/// Lazy-initialized global singleton TimerManager used for shared timing across pipeline components.
#[allow(dead_code)]
static TIMER_MANAGER_INSTANCE: LazyLock<Mutex<TimerManager>> =
    LazyLock::new(|| Mutex::new(TimerManager::new()));

/// TimerManager-specific logic, including access to the global singleton.
impl TimerManager {
    /// Creates a new timer instance with no deadline set.
    pub(crate) fn new() -> Self {
        TimerManager { deadline: None }
    }

    /// Provides global access to a shared singleton TimerManager protected by a mutex.
    #[allow(dead_code)]
    pub(crate) fn global() -> LockResult<MutexGuard<'static, TimerManager>> {
        TIMER_MANAGER_INSTANCE.lock()
    }

    #[allow(dead_code)]
    fn start(&mut self, duration: Duration) {
        self.deadline = Some(Instant::now() + duration);
    }

    /// Checks if the timer has expired and returns a `BackoffExpired` event if so.
    fn poll(&mut self) -> Option<PipelineEvent> {
        if let Some(deadline) = self.deadline {
            if Instant::now() >= deadline {
                self.deadline = None;
                return Some(PipelineEvent::BackoffExpired);
            }
        }

        None
    }
}
