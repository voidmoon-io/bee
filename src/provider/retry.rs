//! Retry provider requests before they produce output. Stream consumption stays with the caller.

use std::{
    future::Future,
    time::{Duration, Instant},
};

use super::ModelError;

pub(crate) async fn request<T, F, Fut>(
    mut send: F,
    max_retries: u32,
    deadline: Option<Instant>,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ModelError>>,
{
    for attempt in 0..=max_retries {
        let reply = if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                return Err("episode deadline exceeded".into());
            }
            tokio::time::timeout_at(deadline.into(), send())
                .await
                .map_err(|_| "episode deadline exceeded".to_string())?
        } else {
            send().await
        };
        match reply {
            Ok(value) => return Ok(value),
            Err(ModelError::Transient {
                status,
                retry_after,
            }) => {
                if attempt == max_retries {
                    return Err(format!(
                        "transient provider error (status {status}) after {attempt} retries"
                    ));
                }
                let delay = retry_after
                    .unwrap_or_else(|| Duration::from_millis(200 * 2u64.pow(attempt.min(6))));
                if let Some(deadline) = deadline {
                    if delay >= deadline.saturating_duration_since(Instant::now()) {
                        tokio::time::sleep_until(deadline.into()).await;
                        return Err("episode deadline exceeded".into());
                    }
                }
                tokio::time::sleep(delay).await;
            }
            Err(ModelError::Auth) => return Err("provider authentication failed".into()),
            Err(ModelError::Request(m)) => return Err(format!("provider rejected request: {m}")),
            Err(ModelError::Decode(m)) => return Err(format!("could not decode response: {m}")),
        }
    }
    unreachable!("the last attempt always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test(start_paused = true)]
    async fn transient_failure_can_recover() {
        let calls = Cell::new(0);
        let value = request(
            || {
                calls.set(calls.get() + 1);
                let attempt = calls.get();
                async move {
                    if attempt == 1 {
                        Err(ModelError::Transient {
                            status: 503,
                            retry_after: None,
                        })
                    } else {
                        Ok("recovered")
                    }
                }
            },
            1,
            None,
        )
        .await
        .unwrap();
        assert_eq!(value, "recovered");
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_cancels_inflight_request() {
        let result: Result<(), _> = request(
            std::future::pending,
            3,
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .await;
        assert_eq!(result.unwrap_err(), "episode deadline exceeded");
    }

    #[tokio::test(start_paused = true)]
    async fn honors_retry_after_and_retry_limit() {
        let calls = Cell::new(0);
        let start = tokio::time::Instant::now();
        let result: Result<(), _> = request(
            || {
                calls.set(calls.get() + 1);
                async {
                    Err(ModelError::Transient {
                        status: 429,
                        retry_after: Some(Duration::from_secs(3)),
                    })
                }
            },
            2,
            None,
        )
        .await;
        assert!(result.unwrap_err().contains("after 2 retries"));
        assert_eq!(calls.get(), 3);
        assert_eq!(start.elapsed(), Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_stops_backoff_without_another_request() {
        let calls = Cell::new(0);
        let result: Result<(), _> = request(
            || {
                calls.set(calls.get() + 1);
                async {
                    Err(ModelError::Transient {
                        status: 503,
                        retry_after: Some(Duration::from_secs(30)),
                    })
                }
            },
            3,
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .await;
        assert_eq!(result.unwrap_err(), "episode deadline exceeded");
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn permanent_errors_are_not_retried() {
        let calls = Cell::new(0);
        let result: Result<(), _> = request(
            || {
                calls.set(calls.get() + 1);
                async { Err(ModelError::Auth) }
            },
            5,
            None,
        )
        .await;
        assert_eq!(result.unwrap_err(), "provider authentication failed");
        assert_eq!(calls.get(), 1);
    }
}
