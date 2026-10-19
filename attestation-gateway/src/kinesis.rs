use std::{sync::Arc, time::Duration};

use aws_sdk_kinesis::{
    Client as KinesisClient,
    error::{ProvideErrorMetadata, SdkError},
    operation::put_record::PutRecordError,
    primitives::Blob,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use uuid::Uuid;

use crate::utils::DataReport;

const MAX_ATTEMPTS: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 50;

#[derive(Clone, Copy)]
struct DeliveryConfig {
    queue_capacity: usize,
    byte_capacity: usize,
    concurrency: usize,
    delivery_timeout: Duration,
    drain_timeout: Duration,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 256,
            byte_capacity: 16 * 1024 * 1024,
            concurrency: 8,
            delivery_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Clone)]
pub struct KinesisPublisher {
    inner: Arc<PublisherInner>,
}

struct PublisherInner {
    sender: mpsc::Sender<PendingEvent>,
    bytes: Arc<Semaphore>,
    enabled: bool,
    config: DeliveryConfig,
    shutdown: Mutex<Option<Shutdown>>,
}

struct Shutdown {
    signal: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

struct PendingEvent {
    payload: Vec<u8>,
    partition_key: String,
    queued_at: Instant,
    deadline: Instant,
    _bytes: OwnedSemaphorePermit,
    completed: bool,
}

impl Drop for PendingEvent {
    fn drop(&mut self) {
        if !self.completed {
            record_drop("cancelled");
        }
    }
}

impl KinesisPublisher {
    /// Starts bounded, best-effort analytics delivery on the current Tokio runtime.
    #[must_use]
    pub fn start(client: KinesisClient, stream_arn: Option<String>) -> Self {
        Self::with_config(
            client,
            stream_arn.unwrap_or_default(),
            DeliveryConfig::default(),
        )
    }

    fn with_config(client: KinesisClient, stream_arn: String, config: DeliveryConfig) -> Self {
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let (signal, stop) = oneshot::channel();
        let enabled = !stream_arn.is_empty();
        let task = tokio::spawn(deliver_events(client, stream_arn, receiver, stop, config));
        Self {
            inner: Arc::new(PublisherInner {
                sender,
                bytes: Arc::new(Semaphore::new(config.byte_capacity)),
                enabled,
                config,
                shutdown: Mutex::new(Some(Shutdown { signal, task })),
            }),
        }
    }

    /// Enqueues without waiting for capacity or network I/O. Overload drops analytics.
    #[must_use]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "Reserve capacity before serialization; send consumes the permit"
    )]
    pub fn enqueue(&self, report: &DataReport) -> bool {
        if !self.inner.enabled {
            return false;
        }
        let permit = match self.inner.sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                record_drop("queue_full");
                return false;
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                record_drop("closed");
                return false;
            }
        };
        let Ok(payload) = report.as_vec() else {
            record_drop("serialization");
            return false;
        };
        let size = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let Ok(bytes) = Arc::clone(&self.inner.bytes).try_acquire_many_owned(size) else {
            record_drop("byte_limit");
            return false;
        };
        let queued_at = Instant::now();
        metrics::counter!("kinesis.enqueued").increment(1);
        permit.send(PendingEvent {
            payload,
            partition_key: Uuid::new_v4().simple().to_string(),
            queued_at,
            deadline: queued_at + self.inner.config.delivery_timeout,
            _bytes: bytes,
            completed: false,
        });
        metrics::gauge!("kinesis.queue_depth").set(gauge_count(
            self.inner.sender.max_capacity() - self.inner.sender.capacity(),
        ));
        true
    }

    /// Stops accepting events and drains accepted work within the shutdown budget.
    pub async fn shutdown(&self) {
        let shutdown = self.inner.shutdown.lock().await.take();
        if let Some(Shutdown { signal, mut task }) = shutdown {
            let _ = signal.send(());
            match timeout(self.inner.config.drain_timeout, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "Kinesis analytics worker failed"),
                Err(_) => {
                    tracing::warn!("Kinesis analytics drain deadline exceeded");
                    task.abort();
                    let _ = task.await;
                }
            }
        }
    }
}

fn gauge_count(count: usize) -> f64 {
    f64::from(u32::try_from(count).unwrap_or(u32::MAX))
}

fn record_drop(reason: &'static str) {
    metrics::counter!("kinesis.dropped", "reason" => reason).increment(1);
    metrics::counter!("attestation_gateway.kinesis_put_failure").increment(1);
}

async fn deliver_events(
    client: KinesisClient,
    stream_arn: String,
    mut receiver: mpsc::Receiver<PendingEvent>,
    mut stop: oneshot::Receiver<()>,
    config: DeliveryConfig,
) {
    let mut tasks = JoinSet::new();
    let mut closing = false;
    let mut input_done = false;
    while !input_done || !tasks.is_empty() {
        metrics::gauge!("kinesis.queue_depth").set(gauge_count(receiver.len()));
        metrics::gauge!("kinesis.in_flight").set(gauge_count(tasks.len()));
        tokio::select! {
            _ = &mut stop, if !closing => {
                closing = true;
                receiver.close();
            }
            event = receiver.recv(), if !input_done && tasks.len() < config.concurrency => {
                if let Some(event) = event {
                    tasks.spawn(deliver_event(client.clone(), stream_arn.clone(), event));
                } else {
                    input_done = true;
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "Kinesis analytics task failed");
                }
            }
        }
    }
    metrics::gauge!("kinesis.queue_depth").set(0.0);
    metrics::gauge!("kinesis.in_flight").set(0.0);
}

async fn deliver_event(client: KinesisClient, stream_arn: String, mut event: PendingEvent) {
    if Instant::now() >= event.deadline {
        record_drop("expired");
        event.completed = true;
        return;
    }
    let outcome = match timeout_at(event.deadline, publish(&client, &stream_arn, &event)).await {
        Ok(Ok(())) => {
            metrics::counter!("kinesis.delivered").increment(1);
            "delivered"
        }
        result => {
            let reason = if result.is_err() {
                "deadline"
            } else {
                "publish"
            };
            metrics::counter!("kinesis.failed", "reason" => reason).increment(1);
            metrics::counter!("attestation_gateway.kinesis_put_failure").increment(1);
            tracing::warn!(reason, error = ?result, "Kinesis analytics delivery failed");
            reason
        }
    };
    metrics::histogram!("kinesis.delivery.duration_seconds", "outcome" => outcome, "histogram" => "distribution")
        .record(event.queued_at.elapsed().as_secs_f64());
    event.completed = true;
}

async fn publish(
    client: &KinesisClient,
    stream_arn: &str,
    event: &PendingEvent,
) -> Result<(), SdkError<PutRecordError>> {
    let mut backoff_ms = INITIAL_BACKOFF_MS;
    for attempt in 1..=MAX_ATTEMPTS {
        match client
            .put_record()
            .stream_arn(stream_arn)
            .partition_key(&event.partition_key)
            .data(Blob::new(event.payload.clone()))
            .send()
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                if !is_retryable_put_record_error(&error) || attempt == MAX_ATTEMPTS {
                    return Err(error);
                }
                metrics::counter!("kinesis.retries").increment(1);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2);
            }
        }
    }
    unreachable!("loop returns on success or final failure")
}

fn is_retryable_put_record_error(error: &SdkError<PutRecordError>) -> bool {
    match error {
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => {
            true
        }
        SdkError::ServiceError(context) => {
            let retryable_code = matches!(
                ProvideErrorMetadata::code(context.err()),
                Some(
                    "InternalFailure"
                        | "ServiceUnavailable"
                        | "ProvisionedThroughputExceededException"
                        | "LimitExceededException"
                )
            );
            retryable_code || context.raw().status().as_u16() >= 500
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
