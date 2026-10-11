//! Pacing for model-originated traffic (019 T054, research R15): a token bucket at `limits.rps` and
//! a semaphore at `limits.concurrency`.
//!
//! Enforced in the **worker**, so a harness bug — or a harness that sends faster — cannot exceed the
//! policy (proxy-control invariant 4).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// A token bucket of capacity `rps` refilled at `rps` tokens per second, plus a concurrency cap.
pub struct Pacer {
    rps: u32,
    bucket: Mutex<Bucket>,
    slots: Arc<Semaphore>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Pacer {
    pub fn new(rps: u32, concurrency: u32) -> Self {
        let rps = rps.max(1);
        Pacer {
            rps,
            bucket: Mutex::new(Bucket {
                tokens: f64::from(rps),
                last: Instant::now(),
            }),
            slots: Arc::new(Semaphore::new(concurrency.max(1) as usize)),
        }
    }

    /// Wait for a concurrency slot and a token. Hold the permit for the request's lifetime.
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("pacer semaphore is never closed");
        loop {
            let wait = {
                let mut b = self.bucket.lock().await;
                let now = Instant::now();
                let refill = now.duration_since(b.last).as_secs_f64() * f64::from(self.rps);
                b.tokens = (b.tokens + refill).min(f64::from(self.rps));
                b.last = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        (1.0 - b.tokens) / f64::from(self.rps),
                    ))
                }
            };
            match wait {
                None => return permit,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A burst of `rps` is admitted at once; after that, admission is exactly the refill rate.
    #[tokio::test(start_paused = true)]
    async fn the_bucket_admits_exactly_rps() {
        let p = Pacer::new(5, 100);
        let start = Instant::now();
        let mut permits = Vec::new();
        for _ in 0..15 {
            permits.push(p.acquire().await);
        }
        // 5 immediately, then 10 more at 5/s = 2s.
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1990) && elapsed <= Duration::from_millis(2100),
            "{elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrency_is_capped() {
        let p = Arc::new(Pacer::new(1000, 2));
        let a = p.acquire().await;
        let _b = p.acquire().await;
        let p2 = p.clone();
        let third = tokio::spawn(async move { p2.acquire().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!third.is_finished(), "a third concurrent request waited");
        drop(a);
        let _admitted = tokio::time::timeout(Duration::from_secs(1), third)
            .await
            .expect("admitted once a slot frees")
            .unwrap();
    }
}
