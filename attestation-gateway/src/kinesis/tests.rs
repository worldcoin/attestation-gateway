#![allow(
    clippy::significant_drop_tightening,
    reason = "Keep test resources alive for assertions; moved events and permits are already consumed"
)]

use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::Engine;
use serde_json::{Value, json};

use super::*;
use crate::utils::BundleIdentifier;

#[derive(Clone)]
struct BackendState {
    requests: Arc<AtomicUsize>,
    release: Arc<Semaphore>,
    bodies: Arc<Mutex<Vec<Value>>>,
    error: Option<(StatusCode, &'static str)>,
}

struct Backend {
    state: BackendState,
    client: KinesisClient,
    task: JoinHandle<()>,
}

impl Backend {
    async fn start(error: Option<(StatusCode, &'static str)>) -> Self {
        let state = BackendState {
            requests: Arc::default(),
            release: Arc::new(Semaphore::new(0)),
            bodies: Arc::default(),
            error,
        };
        let app = Router::new().route("/", post(|State(state): State<BackendState>, body: axum::body::Bytes| async move {
            state.bodies.lock().await.push(serde_json::from_slice(&body).unwrap());
            state.requests.fetch_add(1, Ordering::SeqCst);
            state.release.acquire().await.unwrap().forget();
            if let Some((status, code)) = state.error {
                (status, Json(json!({"__type": code, "message": "test error"})))
            } else {
                (StatusCode::OK, Json(json!({"SequenceNumber": "1", "ShardId": "shardId-000000000000"})))
            }
        })).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = aws_sdk_kinesis::config::Builder::new()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_kinesis::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_kinesis::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(endpoint)
            .retry_config(aws_sdk_kinesis::config::retry::RetryConfig::disabled())
            .build();
        Self {
            state,
            client: KinesisClient::from_conf(config),
            task,
        }
    }

    fn publisher(&self, config: DeliveryConfig) -> KinesisPublisher {
        KinesisPublisher::with_config(
            self.client.clone(),
            "arn:aws:kinesis:us-east-1:000000000000:stream/test".to_string(),
            config,
        )
    }

    async fn wait_for_requests(&self, count: usize) {
        wait_until(|| self.state.requests.load(Ordering::SeqCst) == count).await;
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.state.release.add_permits(100);
        self.task.abort();
    }
}

async fn wait_until(condition: impl Fn() -> bool + Send + Sync) {
    timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

fn report() -> DataReport {
    DataReport::from_client_error(
        "test-error".to_string(),
        "test-hash".to_string(),
        BundleIdentifier::ComWorldcoinStaging,
        "test-audience".to_string(),
        None,
    )
}

#[tokio::test]
async fn queue_is_nonblocking_bounded_and_drains_on_shutdown() {
    let backend = Backend::start(None).await;
    let config = DeliveryConfig {
        queue_capacity: 2,
        concurrency: 1,
        ..DeliveryConfig::default()
    };
    let publisher = backend.publisher(config);
    assert!(publisher.enqueue(&report()));
    backend.wait_for_requests(1).await;
    assert!(publisher.enqueue(&report()));
    assert!(publisher.enqueue(&report()));
    assert!(!publisher.enqueue(&report()));
    assert_eq!(publisher.inner.sender.capacity(), 0);
    // No response has been released: only the configured number of requests may start.
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 1);
    backend.state.release.add_permits(3);
    publisher.shutdown().await;
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 3);
    assert_eq!(
        publisher.inner.bytes.available_permits(),
        config.byte_capacity
    );
    assert!(!publisher.enqueue(&report()));
    let bodies = backend.state.bodies.lock().await;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(bodies[0]["Data"].as_str().unwrap())
        .unwrap();
    let decoded: DataReport = serde_json::from_slice(&payload).unwrap();
    assert_eq!(decoded.request_hash, "test-hash");
    assert_eq!(decoded.client_error.as_deref(), Some("test-error"));
}

#[tokio::test]
async fn byte_budget_includes_in_flight_events_and_is_released() {
    let backend = Backend::start(None).await;
    let report = report();
    let config = DeliveryConfig {
        byte_capacity: report.as_vec().unwrap().len(),
        ..DeliveryConfig::default()
    };
    let publisher = backend.publisher(config);
    assert!(publisher.enqueue(&report));
    backend.wait_for_requests(1).await;
    assert!(!publisher.enqueue(&report));
    assert!(publisher.inner.sender.capacity() > 0);
    backend.state.release.add_permits(1);
    wait_until(|| publisher.inner.bytes.available_permits() == config.byte_capacity).await;
    assert!(publisher.enqueue(&report));
    backend.state.release.add_permits(1);
    publisher.shutdown().await;
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn delivery_deadline_releases_stalled_work() {
    let backend = Backend::start(None).await;
    let config = DeliveryConfig {
        delivery_timeout: Duration::from_millis(100),
        ..DeliveryConfig::default()
    };
    let publisher = backend.publisher(config);
    assert!(publisher.enqueue(&report()));
    backend.wait_for_requests(1).await;
    timeout(Duration::from_secs(2), publisher.shutdown())
        .await
        .unwrap();
    assert_eq!(
        publisher.inner.bytes.available_permits(),
        config.byte_capacity
    );
}

#[tokio::test]
async fn expired_event_does_not_call_kinesis() {
    let backend = Backend::start(None).await;
    let bytes = Arc::new(Semaphore::new(1));
    let event = PendingEvent {
        payload: Vec::new(),
        partition_key: "test".to_string(),
        queued_at: Instant::now() - Duration::from_secs(1),
        deadline: Instant::now(),
        _bytes: Arc::clone(&bytes).acquire_owned().await.unwrap(),
        completed: false,
    };
    deliver_event(backend.client.clone(), "test".to_string(), event).await;
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 0);
    assert_eq!(bytes.available_permits(), 1);
}

#[tokio::test]
async fn retries_are_bounded_and_preserve_record_identity() {
    let backend = Backend::start(Some((
        StatusCode::INTERNAL_SERVER_ERROR,
        "ProvisionedThroughputExceededException",
    )))
    .await;
    let publisher = backend.publisher(DeliveryConfig::default());
    backend.state.release.add_permits(3);
    assert!(publisher.enqueue(&report()));
    publisher.shutdown().await;
    let bodies = backend.state.bodies.lock().await;
    assert_eq!(bodies.len(), 3);
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[1], bodies[2]);
}

#[tokio::test]
async fn permanent_errors_are_not_retried() {
    let backend = Backend::start(Some((StatusCode::BAD_REQUEST, "InvalidArgumentException"))).await;
    backend.state.release.add_permits(3);
    let publisher = backend.publisher(DeliveryConfig::default());
    assert!(publisher.enqueue(&report()));
    publisher.shutdown().await;
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn drain_deadline_releases_in_flight_and_queued_events() {
    let backend = Backend::start(None).await;
    let config = DeliveryConfig {
        concurrency: 1,
        drain_timeout: Duration::from_millis(50),
        delivery_timeout: Duration::from_secs(30),
        ..DeliveryConfig::default()
    };
    let publisher = backend.publisher(config);
    assert!(publisher.enqueue(&report()));
    backend.wait_for_requests(1).await;
    assert!(publisher.enqueue(&report()));
    assert!(publisher.enqueue(&report()));
    timeout(Duration::from_secs(2), publisher.shutdown())
        .await
        .unwrap();
    wait_until(|| publisher.inner.bytes.available_permits() == config.byte_capacity).await;
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 1);
    assert!(!publisher.enqueue(&report()));
}

#[tokio::test]
async fn absent_stream_disables_delivery() {
    let backend = Backend::start(None).await;
    let publisher = KinesisPublisher::start(backend.client.clone(), None);
    assert!(!publisher.enqueue(&report()));
    publisher.shutdown().await;
    assert_eq!(backend.state.requests.load(Ordering::SeqCst), 0);
}
