//! Online Workers
//!
//! Handles network-dependent operations including:
//! - Task fetching from the orchestrator
//! - Proof submission to the orchestrator
//! - Network error handling with exponential backoff

use crate::consts::prover::{
    BACKOFF_DURATION, BATCH_SIZE, LOW_WATER_MARK, MAX_404S_BEFORE_GIVING_UP, QUEUE_LOG_INTERVAL,
    TASK_QUEUE_SIZE,
};
use crate::error_classifier::{ErrorClassifier, LogLevel};
use crate::events::Event;
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::task::Task;
use crate::task_cache::TaskCache;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nexus_sdk::stwo::seq::Proof;
use sha3::{Digest, Keccak256};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// State for managing task fetching behavior
pub struct TaskFetchState {
    last_fetch_time: std::time::Instant,
    backoff_duration: Duration,
    last_queue_log_time: std::time::Instant,
    queue_log_interval: Duration,
    error_classifier: ErrorClassifier,
}

impl TaskFetchState {
    pub fn new() -> Self {
        Self {
            last_fetch_time: std::time::Instant::now()
                - Duration::from_millis(BACKOFF_DURATION + 1000), // Allow immediate first fetch
            backoff_duration: Duration::from_millis(BACKOFF_DURATION), // Start with 30 second backoff
            last_queue_log_time: std::time::Instant::now(),
            queue_log_interval: Duration::from_millis(QUEUE_LOG_INTERVAL), // Log queue status every 30 seconds
            error_classifier: ErrorClassifier::new(),
        }
    }

    pub fn should_log_queue_status(&mut self) -> bool {
        // Log queue status every QUEUE_LOG_INTERVAL seconds regardless of queue level
        self.last_queue_log_time.elapsed() >= self.queue_log_interval
    }

    pub fn should_fetch(&self, tasks_in_queue: usize) -> bool {
        tasks_in_queue < LOW_WATER_MARK && self.last_fetch_time.elapsed() >= self.backoff_duration
    }

    pub fn record_fetch_attempt(&mut self) {
        self.last_fetch_time = std::time::Instant::now();
    }

    pub fn record_queue_log(&mut self) {
        self.last_queue_log_time = std::time::Instant::now();
    }

    pub fn reset_backoff(&mut self) {
        self.backoff_duration = Duration::from_millis(BACKOFF_DURATION);
    }

    pub fn increase_backoff_for_rate_limit(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 2,
            Duration::from_millis(BACKOFF_DURATION * 2),
        );
    }

    pub fn increase_backoff_for_error(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 2,
            Duration::from_millis(BACKOFF_DURATION * 2),
        );
    }
}

/// Fetches tasks from the orchestrator and place them in the task queue.
/// Uses demand-driven fetching: only fetches when queue drops below LOW_WATER_MARK.
pub async fn fetch_prover_tasks(
    node_id: u64,
    verifying_key: VerifyingKey,
    orchestrator_client: Box<dyn Orchestrator>,
    sender: mpsc::Sender<Task>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    recent_tasks: TaskCache,
) {
    let mut state = TaskFetchState::new();

    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();

                // Log queue status every QUEUE_LOG_INTERVAL seconds regardless of queue level
                if state.should_log_queue_status() {
                    state.record_queue_log();
                    log_queue_status(&event_sender, tasks_in_queue, &state).await;
                }

                // Attempt fetch if conditions are met
                if state.should_fetch(tasks_in_queue) {
                    if let Err(should_return) = attempt_task_fetch(
                        &*orchestrator_client,
                        &node_id,
                        verifying_key,
                        &sender,
                        &event_sender,
                        &recent_tasks,
                        &mut state,
                    ).await {
                        if should_return {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Attempt to fetch tasks with timeout and error handling
async fn attempt_task_fetch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
) -> Result<(), bool> {
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            format!(
                "🔍 Fetching tasks (queue: {} tasks)",
                TASK_QUEUE_SIZE - sender.capacity()
            ),
            crate::events::EventType::Refresh,
            LogLevel::Debug,
        ))
        .await;

    // Add timeout to prevent hanging
    let fetch_future = fetch_task_batch(
        orchestrator_client,
        node_id,
        verifying_key,
        BATCH_SIZE,
        event_sender,
    );
    let timeout_duration = Duration::from_secs(60); // 60 second timeout

    match tokio::time::timeout(timeout_duration, fetch_future).await {
        Ok(fetch_result) => match fetch_result {
            Ok(tasks) => {
                // Record successful fetch attempt timing
                state.record_fetch_attempt();
                handle_fetch_success(tasks, sender, event_sender, recent_tasks, state).await
            }
            Err(e) => {
                // Record failed fetch attempt timing
                state.record_fetch_attempt();
                handle_fetch_error(e, event_sender, state).await;
                Ok(())
            }
        },
        Err(_timeout) => {
            // Handle timeout case
            state.record_fetch_attempt();
            let _ = event_sender
                .send(Event::task_fetcher_with_level(
                    format!("⏰ Fetch timeout after {}s", timeout_duration.as_secs()),
                    crate::events::EventType::Error,
                    LogLevel::Warn,
                ))
                .await;
            // Increase backoff for timeout
            state.increase_backoff_for_error();
            Ok(())
        }
    }
}

/// Log the current queue status
async fn log_queue_status(
    event_sender: &mpsc::Sender<Event>,
    tasks_in_queue: usize,
    state: &TaskFetchState,
) {
    let time_since_last = state.last_fetch_time.elapsed();
    let backoff_secs = state.backoff_duration.as_secs();

    let message = if state.should_fetch(tasks_in_queue) {
        format!("⚡ Queue low: {} tasks, ready to fetch", tasks_in_queue)
    } else {
        let time_since_secs = time_since_last.as_secs();
        format!(
            "⚡ Queue low: {} tasks, waiting {}s more (retry every {}s)",
            tasks_in_queue,
            backoff_secs.saturating_sub(time_since_secs),
            backoff_secs
        )
    };

    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            message,
            crate::events::EventType::Refresh,
            LogLevel::Debug,
        ))
        .await;
}

/// Handle successful task fetch
async fn handle_fetch_success(
    tasks: Vec<Task>,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
) -> Result<(), bool> {
    if tasks.is_empty() {
        handle_empty_task_response(sender, event_sender, state).await;
        return Ok(());
    }

    let (added_count, duplicate_count) =
        process_fetched_tasks(tasks, sender, event_sender, recent_tasks).await?;

    log_fetch_results(added_count, duplicate_count, sender, event_sender, state).await;
    Ok(())
}

/// Handle empty task response from server
async fn handle_empty_task_response(
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    let current_queue_level = TASK_QUEUE_SIZE - sender.capacity();
    let msg = format!(
        "💤 No tasks available (queue: {} tasks)",
        current_queue_level
    );
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Info,
        ))
        .await;

    // IMPORTANT: Reset backoff even when no tasks are available
    // Otherwise we get stuck in backoff loop when server has no tasks
    state.reset_backoff();
}

/// Process fetched tasks and handle duplicates
async fn process_fetched_tasks(
    tasks: Vec<Task>,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
) -> Result<(usize, usize), bool> {
    let mut added_count = 0;
    let mut duplicate_count = 0;

    for task in tasks {
        if recent_tasks.contains(&task.task_id).await {
            duplicate_count += 1;
            continue;
        }
        recent_tasks.insert(task.task_id.clone()).await;

        if sender.send(task.clone()).await.is_err() {
            let _ = event_sender
                .send(Event::task_fetcher(
                    "Task queue is closed".to_string(),
                    crate::events::EventType::Shutdown,
                ))
                .await;
            return Err(true); // Signal caller to return
        }
        added_count += 1;
    }

    Ok((added_count, duplicate_count))
}

/// Log fetch results and handle backoff logic
async fn log_fetch_results(
    added_count: usize,
    duplicate_count: usize,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    if added_count > 0 {
        log_successful_fetch(added_count, sender, event_sender).await;
        state.reset_backoff();
    } else if duplicate_count > 0 {
        handle_all_duplicates(duplicate_count, event_sender, state).await;
    }
}

/// Log successful task fetch with queue status
async fn log_successful_fetch(
    added_count: usize,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
) {
    let current_queue_level = TASK_QUEUE_SIZE - sender.capacity();
    let queue_percentage = (current_queue_level as f64 / TASK_QUEUE_SIZE as f64 * 100.0) as u32;

    // Enhanced queue status logging
    let msg = if added_count >= 5 {
        format!(
            "Queue status: +{} tasks → {} total ({}/{}={queued_percentage}% full)",
            added_count,
            current_queue_level,
            current_queue_level,
            TASK_QUEUE_SIZE,
            queued_percentage = queue_percentage
        )
    } else {
        format!(
            "Queue status: +{} tasks → {} total ({}% full)",
            added_count, current_queue_level, queue_percentage
        )
    };

    // Log level based on queue fullness
    let log_level = if queue_percentage >= 80 || added_count >= 5 {
        LogLevel::Info // High queue level or significant additions are important
    } else {
        LogLevel::Debug // Minor additions are debug level
    };

    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            msg,
            crate::events::EventType::Refresh,
            log_level,
        ))
        .await;
}

/// Handle case where all fetched tasks were duplicates
async fn handle_all_duplicates(
    duplicate_count: usize,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    // All duplicates - significant backoff increase
    state.increase_backoff_for_error();
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            format!(
                "🔄 All {} tasks were duplicates - backing off for {}s",
                duplicate_count,
                state.backoff_duration.as_secs()
            ),
            crate::events::EventType::Refresh,
            LogLevel::Warn,
        ))
        .await;
}

/// Handle fetch errors with appropriate backoff
async fn handle_fetch_error(
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    if matches!(error, OrchestratorError::Http { status: 429, .. }) {
        state.increase_backoff_for_rate_limit();
        let _ = event_sender
            .send(Event::task_fetcher_with_level(
                format!(
                    "⏳ Rate limited - retrying in {}s",
                    state.backoff_duration.as_secs()
                ),
                crate::events::EventType::Error,
                LogLevel::Warn,
            ))
            .await;
    } else {
        state.increase_backoff_for_error();
        let log_level = state.error_classifier.classify_fetch_error(&error);
        let event = Event::task_fetcher_with_level(
            format!(
                "Failed to fetch tasks: {}, retrying in {} seconds",
                error,
                state.backoff_duration.as_secs()
            ),
            crate::events::EventType::Error,
            log_level,
        );
        if event.should_display() {
            let _ = event_sender.send(event).await;
        }
    }
}

/// Fetch a batch of tasks from the orchestrator
async fn fetch_task_batch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    batch_size: usize,
    event_sender: &mpsc::Sender<Event>,
) -> Result<Vec<Task>, OrchestratorError> {
    // First try to get existing assigned tasks
    if let Some(existing_tasks) = try_get_existing_tasks(orchestrator_client, node_id).await? {
        return Ok(existing_tasks);
    }

    // If no existing tasks, try to get new ones
    fetch_new_tasks_batch(
        orchestrator_client,
        node_id,
        verifying_key,
        batch_size,
        event_sender,
    )
    .await
}

/// Try to get existing assigned tasks
async fn try_get_existing_tasks(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
) -> Result<Option<Vec<Task>>, OrchestratorError> {
    match orchestrator_client.get_tasks(&node_id.to_string()).await {
        Ok(tasks) => {
            if !tasks.is_empty() {
                Ok(Some(tasks))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            // If getting existing tasks fails, try to get new ones
            if matches!(e, OrchestratorError::Http { status: 404, .. }) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Fetch a batch of new tasks from the orchestrator
async fn fetch_new_tasks_batch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    batch_size: usize,
    event_sender: &mpsc::Sender<Event>,
) -> Result<Vec<Task>, OrchestratorError> {
    let mut new_tasks = Vec::new();
    let mut consecutive_404s = 0;

    for i in 0..batch_size {
        match orchestrator_client
            .get_proof_task(&node_id.to_string(), verifying_key)
            .await
        {
            Ok(task) => {
                new_tasks.push(task);
                consecutive_404s = 0; // Reset counter on success
            }
            Err(OrchestratorError::Http { status: 429, .. }) => {
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        "⏳ Rate limited during batch fetch".to_string(),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;
                // Rate limited, return what we have
                break;
            }
            Err(OrchestratorError::Http { status: 404, .. }) => {
                consecutive_404s += 1;
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!("fetch_task_batch: No task available (404) on attempt #{}, consecutive_404s: {}", i + 1, consecutive_404s),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;

                if consecutive_404s >= MAX_404S_BEFORE_GIVING_UP {
                    let _ = event_sender
                        .send(Event::task_fetcher_with_level(
                            format!(
                                "fetch_task_batch: Too many 404s ({}), giving up",
                                consecutive_404s
                            ),
                            crate::events::EventType::Refresh,
                            LogLevel::Debug,
                        ))
                        .await;
                    break;
                }
                // Continue trying more tasks
            }
            Err(e) => {
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!(
                            "fetch_task_batch: get_proof_task #{} failed with error: {:?}",
                            i + 1,
                            e
                        ),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;
                return Err(e);
            }
        }
    }

    Ok(new_tasks)
}

/// Submits proofs to the orchestrator with retry support
pub async fn submit_proofs(
    signing_key: SigningKey,
    orchestrator: Box<dyn Orchestrator>,
    num_workers: usize,
    mut results: mpsc::Receiver<(Task, Proof)>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    successful_tasks: TaskCache,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut completed_count = 0;
        let mut retry_count = 0;
        let mut last_stats_time = std::time::Instant::now();
        let stats_interval = Duration::from_secs(60);

        loop {
            tokio::select! {
                maybe_item = results.recv() => {
                    match maybe_item {
                        Some((task, proof)) => {
                            if let Some(success) = process_proof_submission(
                                task,
                                proof,
                                &*orchestrator,
                                &signing_key,
                                num_workers,
                                &event_sender,
                                &successful_tasks,
                            ).await {
                                if success {
                                    completed_count += 1;
                                }
                                // Increment retry count if this was a retry (tracked internally in process_proof_submission)
                            }

                            // Check if it's time to report stats (avoid timer starvation)
                            if last_stats_time.elapsed() >= stats_interval {
                                report_performance_stats(&event_sender, completed_count, retry_count, last_stats_time).await;
                                completed_count = 0;
                                retry_count = 0;
                                last_stats_time = std::time::Instant::now();
                            }
                        }
                        None => break,
                    }
                }

                _ = tokio::time::sleep(stats_interval) => {
                    // Fallback timer in case there's no activity
                    report_performance_stats(&event_sender, completed_count, retry_count, last_stats_time).await;
                    completed_count = 0;
                    retry_count = 0;
                    last_stats_time = std::time::Instant::now();
                }

                _ = shutdown.recv() => break,
            }
        }
    })
}

/// Report performance statistics with retry information
async fn report_performance_stats(
    event_sender: &mpsc::Sender<Event>,
    completed_count: u64,
    retry_count: u64,
    last_stats_time: std::time::Instant,
) {
    let elapsed = last_stats_time.elapsed();
    let tasks_per_minute = if elapsed.as_secs() > 0 {
        (completed_count as f64 * 60.0) / elapsed.as_secs() as f64
    } else {
        0.0
    };

    let retry_info = if retry_count > 0 {
        format!(" ({} retries)", retry_count)
    } else {
        String::new()
    };

    let msg = format!(
        "📊 Performance: {} tasks in {:.1}s{} ({:.1} tasks/min)",
        completed_count,
        elapsed.as_secs_f64(),
        retry_info,
        tasks_per_minute
    );
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Info,
        ))
        .await;
}

/// Process a single proof submission with retry logic
/// Returns Some(true) if successful, Some(false) if failed after retries, None if should skip
async fn process_proof_submission(
    task: Task,
    proof: Proof,
    orchestrator: &dyn Orchestrator,
    signing_key: &SigningKey,
    num_workers: usize,
    event_sender: &mpsc::Sender<Event>,
    successful_tasks: &TaskCache,
) -> Option<bool> {
    // Check for duplicate submissions
    if successful_tasks.contains(&task.task_id).await {
        let msg = format!(
            "Ignoring proof for previously submitted task {}",
            task.task_id
        );
        let _ = event_sender
            .send(Event::proof_submitter(msg, crate::events::EventType::Error))
            .await;
        return None; // Skip this task
    }

    // Serialize proof
    let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
    let proof_hash = format!("{:x}", Keccak256::digest(&proof_bytes));

    // Retry configuration
    const MAX_RETRIES: usize = 6;
    const INITIAL_RETRY_DELAY_MS: u64 = 1000; // 1 second

    // Submit to orchestrator with retries
    for retry in 0..=MAX_RETRIES {
        let is_retry = retry > 0;
        
        if is_retry {
            let msg = format!(
                "Retrying proof submission for task {} (attempt {}/{})",
                task.task_id, retry, MAX_RETRIES
            );
            let _ = event_sender
                .send(Event::proof_submitter_with_level(
                    msg,
                    crate::events::EventType::Refresh,
                    LogLevel::Info,
                ))
                .await;
        }

        match orchestrator
            .submit_proof(
                &task.task_id,
                &proof_hash,
                proof_bytes.clone(), // Clone for retry
                signing_key.clone(),
                num_workers,
            )
            .await
        {
            Ok(_) => {
                handle_submission_success(&task, event_sender, successful_tasks).await;
                return Some(true);
            }
            Err(e) => {
                // Don't retry on certain errors
                if should_abort_retries(&e) || retry == MAX_RETRIES {
                    handle_submission_error(&task, e, event_sender).await;
                    return Some(false);
                }
                
                // Log the error but continue to retry
                let retry_msg = format!(
                    "Submission attempt {} failed: {}. Will retry in {}ms",
                    retry + 1,
                    e,
                    INITIAL_RETRY_DELAY_MS * 2u64.pow(retry as u32)
                );
                let _ = event_sender
                    .send(Event::proof_submitter_with_level(
                        retry_msg,
                        crate::events::EventType::Error,
                        LogLevel::Warn,
                    ))
                    .await;
                
                // Exponential backoff
                let delay = INITIAL_RETRY_DELAY_MS * 2u64.pow(retry as u32);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
    }
    
    // This should never be reached due to the return in the last retry
    Some(false)
}

/// Handle successful proof submission
async fn handle_submission_success(
    task: &Task,
    event_sender: &mpsc::Sender<Event>,
    successful_tasks: &TaskCache,
) {
    successful_tasks.insert(task.task_id.clone()).await;
    let msg = "📤 Proof submitted".to_string();
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            msg,
            crate::events::EventType::Success,
            LogLevel::Info,
        ))
        .await;
}

/// Handle proof submission errors with improved error categorization
async fn handle_submission_error(
    task: &Task,
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
) {
    let (msg, log_level) = match &error {
        OrchestratorError::Http { status, .. } => {
            let status_msg = match status {
                400 => "Bad request (invalid proof format)",
                401 => "Unauthorized (authentication failed)",
                403 => "Forbidden (not authorized for this task)",
                404 => "Task not found (may have been completed by another prover)",
                408 => "Request timeout",
                429 => "Rate limited (too many submissions)",
                500 => "Server error (internal error)",
                502 => "Bad gateway (server error)",
                503 => "Service unavailable (server overloaded)",
                504 => "Gateway timeout (server took too long)",
                _ => "Unknown HTTP error",
            };
            
            (
                format!(
                    "Failed to submit proof for task {}. Status {}: {}",
                    task.task_id, status, status_msg
                ),
                if *status >= 500 { LogLevel::Warn } else { LogLevel::Error }
            )
        }
        e => (
            format!("Failed to submit proof for task {}: {}", task.task_id, e),
            LogLevel::Error
        ),
    };

    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            msg, 
            crate::events::EventType::Error,
            log_level
        ))
        .await;
}

/// Determine if we should abort retries based on error type
fn should_abort_retries(error: &OrchestratorError) -> bool {
    match error {
        // Don't retry for client errors that won't be resolved by retrying
        OrchestratorError::Http { status, .. } => {
            // Don't retry for 400, 401, 403 (client errors that won't be fixed by retrying)
            // Do retry for 408, 429, 500, 502, 503, 504 (temporary server issues)
            matches!(status, 400 | 401 | 403 | 404)
        }
        // Other errors like serialization might be worth retrying
        _ => false,
    }
}
