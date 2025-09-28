//! Generic FSM runtime: keyed states, pluggable handlers and intent emission
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::logic::context::StateContext;
use crate::logic::intent::Intent;
use crate::logic::pipeline::{Pipeline, PipelineEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;

/// Trait bound for enum-like state keys used by the FSM.
/// Must be hashable, cloneable, serializable and printable for logs/telemetry
pub trait StateKeyLike:
    Eq + Hash + Clone + Display + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static
{
}
impl<T> StateKeyLike for T where
    T: Eq + Hash + Clone + Display + Send + Sync + Serialize + for<'de> Deserialize<'de> + 'static
{
}

/// Registry mapping a state key to its handler implementation.
pub struct FsmRegistry<K: StateKeyLike> {
    pub(crate) handlers: HashMap<K, Box<dyn StateHandler<K>>>,
}

/// Decision returned by a state handler.
/// Stay(intents) keeps current state
/// Transition switches to the to
pub(crate) enum TransitionDecision<K> {
    Stay(Vec<Intent>),
    Transition {
        to: K,
        reason: String,
        intents: Vec<Intent>,
    },
}

/// Per-state event handler: receives the pipeline, shared context, and event and returns a decision plus any intents to emit
pub trait StateHandler<K: StateKeyLike>: Send + Sync {
    fn on_event(
        &mut self,
        pipeline: &mut Pipeline,
        ctx: &mut StateContext,
        event: &PipelineEvent,
    ) -> TransitionDecision<K>;
}

impl<K: StateKeyLike> FsmRegistry<K> {
    /// Register a handler for a given state key
    pub(crate) fn register(&mut self, state: K, handler: Box<dyn StateHandler<K>>) {
        self.handlers.insert(state.clone(), handler);
    }

    /// Route an event to the current state's handler and return next_state, intents
    /// If a transition occurs, LogTransition is inserted
    /// Caller is responsible for persisting next_state and enqueueing the intents.
    pub(crate) fn handle<F>(
        &mut self,
        pipeline: &mut Pipeline,
        ctx: &mut StateContext,
        event: &PipelineEvent,
        get_state: F,
    ) -> (K, Vec<Intent>)
    where
        F: Fn(&StateContext) -> &K,
    {
        let state = get_state(ctx).clone();
        if let Some(handler) = self.handlers.get_mut(&state) {
            match handler.on_event(pipeline, ctx, event) {
                TransitionDecision::Stay(intents) => (state.clone(), intents),
                TransitionDecision::Transition {
                    to,
                    reason,
                    mut intents,
                } => {
                    // Prepend a structured log intent for replay / telemetry.
                    intents.insert(
                        0,
                        Intent::LogTransition {
                            from: format!("{}", state),
                            to: format!("{}", to),
                            triggered_by: Some(event.clone()),
                            reason,
                        },
                    );
                    (to, intents)
                }
            }
        } else {
            // No handler registered: remain in place and emit a NoOp
            (state.clone(), vec![Intent::NoOp])
        }
    }
}
