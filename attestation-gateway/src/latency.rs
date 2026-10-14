use std::{
    future::Future,
    sync::{Arc, OnceLock},
    time::Instant,
};

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};

#[derive(Clone)]
struct Context {
    route: &'static str,
    platform: Arc<OnceLock<&'static str>>,
}

tokio::task_local! {
    static CONTEXT: Context;
}

pub fn set_platform(platform: &'static str) {
    // Only the first classification in a measured request applies; other callers need no context.
    let _ = CONTEXT.try_with(|context| context.platform.set(platform));
}

struct Timer {
    context: Context,
    operation: Option<&'static str>,
    started: Instant,
    outcome: &'static str,
}

impl Timer {
    fn new(context: Context, operation: Option<&'static str>) -> Self {
        Self {
            context,
            operation,
            started: Instant::now(),
            outcome: "cancelled",
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let mut labels = vec![
            metrics::Label::new("route", self.context.route),
            metrics::Label::new(
                "platform",
                self.context.platform.get().copied().unwrap_or("unknown"),
            ),
            metrics::Label::new("outcome", self.outcome),
        ];
        let name = self
            .operation
            .map_or("request.duration_seconds", |operation| {
                labels.push(metrics::Label::new("operation", operation));
                "operation.duration_seconds"
            });
        // DogStatsD distributions aggregate across tasks; host-local percentiles cannot be averaged.
        labels.push(metrics::Label::new("histogram", "distribution"));
        metrics::histogram!(name, labels).record(self.started.elapsed().as_secs_f64());
    }
}

// Install outside the response timeout so HTTP 408s are measured as timeouts, not cancellations.
pub async fn requests(request: Request, next: Next) -> Response {
    let route = match request.uri().path() {
        "/c" => "/c",
        "/a" => "/a",
        "/g" => "/g",
        _ => return next.run(request).await,
    };
    let context = Context {
        route,
        platform: Arc::default(),
    };
    let timer = Timer::new(context.clone(), None);
    CONTEXT
        .scope(context, async move {
            let response = next.run(request).await;
            let outcome = match response.status() {
                StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => "timeout",
                status if status.is_server_error() => "server_error",
                status if status.is_client_error() => "client_error",
                _ => "success",
            };
            timer.finish(outcome);
            response
        })
        .await
}

pub async fn measure<T, E>(
    operation: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let timer = CONTEXT
        .try_with(|context| Timer::new(context.clone(), Some(operation)))
        .ok();
    let result = future.await;
    if let Some(timer) = timer {
        timer.finish(if result.is_ok() { "success" } else { "error" });
    }
    result
}

pub fn measure_sync<T, E>(
    operation: &'static str,
    work: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let timer = CONTEXT
        .try_with(|context| Timer::new(context.clone(), Some(operation)))
        .ok();
    let result = work();
    if let Some(timer) = timer {
        timer.finish(if result.is_ok() { "success" } else { "error" });
    }
    result
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use axum::{Json, Router, body::Body, middleware, routing::post};
    use metrics_exporter_statsd::{StatsdBuilder, StatsdRecorder};
    use tower::ServiceExt;
    use tower_http::timeout::TimeoutLayer;

    use super::*;

    fn recorder() -> (UdpSocket, StatsdRecorder) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let recorder = StatsdBuilder::from("127.0.0.1", socket.local_addr().unwrap().port())
            .with_buffer_size(0)
            .with_queue_size(100)
            .build(Some("attestation_gateway."))
            .unwrap();
        (socket, recorder)
    }

    fn receive(socket: &UdpSocket, count: usize) -> Vec<String> {
        (0..count)
            .map(|_| {
                let mut buffer = [0; 2048];
                let size = socket.recv(&mut buffer).unwrap();
                String::from_utf8(buffer[..size].to_vec()).unwrap()
            })
            .collect()
    }

    fn request(path: &str) -> Request {
        Request::post(path)
            .header("authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap()
    }

    fn sample<'a>(samples: &'a [String], metric: &str, tags: &[&str]) -> &'a str {
        samples
            .iter()
            .find(|sample| {
                sample.starts_with(&format!("attestation_gateway.{metric}:"))
                    && tags.iter().all(|tag| sample.contains(tag))
            })
            .unwrap_or_else(|| panic!("missing {metric} {tags:?}: {samples:?}"))
    }

    #[tokio::test]
    async fn emits_distributions_and_preserves_success_and_error_results() {
        let (socket, recorder) = recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        for (status, outcome) in [
            (StatusCode::OK, "success"),
            (StatusCode::BAD_REQUEST, "client_error"),
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        ] {
            let app = Router::new()
                .route(
                    "/g",
                    post(move || async move {
                        set_platform("android");
                        let result = measure_sync("attestation_verify", || {
                            if status.is_success() { Ok(42) } else { Err(7) }
                        });
                        assert_eq!(result, if status.is_success() { Ok(42) } else { Err(7) });
                        status
                    }),
                )
                .layer(middleware::from_fn(requests));
            let response = app
                .oneshot(request("/g?request_hash=private-value"))
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            let samples = receive(&socket, 2);
            let total = sample(
                &samples,
                "request.duration_seconds",
                &[
                    "route:/g",
                    "platform:android",
                    &format!("outcome:{outcome}"),
                ],
            );
            assert!(total.contains("|d|"));
            let seconds: f64 = total
                .split(':')
                .nth(1)
                .unwrap()
                .split('|')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            assert!(seconds >= 0.0);
            let op_outcome = if status.is_success() {
                "success"
            } else {
                "error"
            };
            sample(
                &samples,
                "operation.duration_seconds",
                &[
                    "operation:attestation_verify",
                    &format!("outcome:{op_outcome}"),
                ],
            );
            for line in samples {
                assert!(
                    !line.contains("secret")
                        && !line.contains("private-value")
                        && !line.contains("histogram:")
                );
            }
        }
    }

    #[tokio::test]
    async fn timeout_records_total_and_cancelled_dependency() {
        let (socket, recorder) = recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let app = Router::new()
            .route(
                "/g",
                post(|| async {
                    set_platform("ios");
                    let _ =
                        measure("apple_key_read", std::future::pending::<Result<(), ()>>()).await;
                    StatusCode::OK
                }),
            )
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_millis(10),
            ))
            .layer(middleware::from_fn(requests));
        let response = app.oneshot(request("/g")).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let samples = receive(&socket, 2);
        sample(
            &samples,
            "request.duration_seconds",
            &["outcome:timeout", "platform:ios"],
        );
        sample(
            &samples,
            "operation.duration_seconds",
            &["outcome:cancelled", "operation:apple_key_read"],
        );
    }

    #[tokio::test]
    async fn caller_cancellation_still_records_request_and_dependency() {
        let (socket, recorder) = recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let app = Router::new()
            .route(
                "/a",
                post(|| async {
                    set_platform("android");
                    let _ = measure("token_sign", std::future::pending::<Result<(), ()>>()).await;
                    StatusCode::OK
                }),
            )
            .layer(middleware::from_fn(requests));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), app.oneshot(request("/a")))
                .await
                .is_err()
        );
        let samples = receive(&socket, 2);
        sample(
            &samples,
            "request.duration_seconds",
            &["route:/a", "outcome:cancelled"],
        );
        sample(
            &samples,
            "operation.duration_seconds",
            &["operation:token_sign", "outcome:cancelled"],
        );
    }

    #[tokio::test]
    async fn concurrent_requests_keep_separate_platform_and_route_tags() {
        let (socket, recorder) = recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let app = Router::new()
            .route(
                "/a",
                post(|| async {
                    set_platform("ios");
                    measure("attestation_verify", async {
                        tokio::task::yield_now().await;
                        Ok::<_, ()>(())
                    })
                    .await
                    .unwrap();
                    StatusCode::OK
                }),
            )
            .route(
                "/g",
                post(|| async {
                    set_platform("android");
                    measure("attestation_verify", async {
                        tokio::task::yield_now().await;
                        Ok::<_, ()>(())
                    })
                    .await
                    .unwrap();
                    StatusCode::OK
                }),
            )
            .layer(middleware::from_fn(requests));
        let (a, g) = tokio::join!(
            app.clone().oneshot(request("/a")),
            app.oneshot(request("/g"))
        );
        assert_eq!(a.unwrap().status(), StatusCode::OK);
        assert_eq!(g.unwrap().status(), StatusCode::OK);
        let samples = receive(&socket, 4);
        for metric in ["request.duration_seconds", "operation.duration_seconds"] {
            sample(&samples, metric, &["route:/a", "platform:ios"]);
            sample(&samples, metric, &["route:/g", "platform:android"]);
        }
    }

    #[tokio::test]
    async fn extractor_rejections_are_counted_and_unrelated_paths_are_excluded() {
        let (socket, recorder) = recorder();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let app = Router::new()
            .route(
                "/c",
                post(|Json(_): Json<serde_json::Value>| async { StatusCode::OK }),
            )
            .layer(middleware::from_fn(requests));
        assert_eq!(
            app.clone()
                .oneshot(request("/health"))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.clone()
                .oneshot(request("/unknown-sensitive-path"))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(measure("background", async { Ok::<_, ()>(3) }).await, Ok(3));
        assert_eq!(
            app.oneshot(request("/c")).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let samples = receive(&socket, 1);
        sample(
            &samples,
            "request.duration_seconds",
            &["route:/c", "outcome:client_error", "platform:unknown"],
        );
    }
}
