use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::info;

#[derive(Clone, Default)]
pub(crate) struct IdleTracker {
    activity: Arc<Notify>,
}

impl IdleTracker {
    pub(crate) fn new() -> Self {
        Self {
            activity: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn record_activity(&self) {
        self.activity.notify_one();
    }

    pub(crate) async fn wait_for_activity(&self) {
        self.activity.notified().await;
    }
}

pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn wait_for_idle_exit(tracker: &IdleTracker, timeout: Duration) {
    loop {
        tokio::select! {
            biased;
            () = tracker.wait_for_activity() => {}
            () = tokio::time::sleep(timeout) => return,
        }
    }
}

pub(crate) async fn run_idle_disconnect_loop<F, Fut>(
    tracker: IdleTracker,
    timeout: Duration,
    mut on_idle: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        tracker.wait_for_activity().await;

        loop {
            tokio::select! {
                biased;
                () = tracker.wait_for_activity() => {}
                () = tokio::time::sleep(timeout) => {
                    on_idle().await;
                    break;
                }
            }
        }
    }
}

pub(crate) async fn run_with_idle_exit<Fut, F, IdleFut>(
    server: Fut,
    tracker: &IdleTracker,
    timeout: Duration,
    on_idle: F,
) -> Result<(), std::io::Error>
where
    Fut: Future<Output = Result<(), std::io::Error>>,
    F: FnOnce() -> IdleFut,
    IdleFut: Future<Output = ()>,
{
    tokio::select! {
        result = server => {
            on_idle().await;
            result
        }
        () = wait_for_idle_exit(tracker, timeout) => {
            info!(?timeout, "idle timeout elapsed; disconnecting and exiting");
            on_idle().await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AbortOnDrop, IdleTracker, run_idle_disconnect_loop, run_with_idle_exit};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn standalone_idle_loop_disconnects_once_and_rearms_after_activity() {
        let tracker = IdleTracker::new();
        let disconnects = Arc::new(AtomicUsize::new(0));
        let disconnects_clone = Arc::clone(&disconnects);

        let _guard = AbortOnDrop(tokio::spawn(run_idle_disconnect_loop(
            tracker.clone(),
            Duration::from_millis(60),
            move || {
                let disconnects_clone = Arc::clone(&disconnects_clone);
                async move {
                    disconnects_clone.fetch_add(1, Ordering::SeqCst);
                }
            },
        )));

        // No activity yet: idle disconnect must not fire.
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 0);

        // Activity arms the timer; further activity before expiry resets it.
        tracker.record_activity();
        tokio::time::sleep(Duration::from_millis(35)).await;
        tracker.record_activity();
        tokio::time::sleep(Duration::from_millis(35)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 0);

        // After full timeout of inactivity, disconnect fires once.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);

        // Staying idle must not busy-loop or re-fire disconnect.
        tokio::time::sleep(Duration::from_millis(140)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);

        // Subsequent activity re-arms the timer and triggers another disconnect.
        tracker.record_activity();
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn socket_activated_idle_exit_resets_on_activity_and_disconnects() {
        let tracker = IdleTracker::new();
        let disconnects = Arc::new(AtomicUsize::new(0));
        let disconnects_clone = Arc::clone(&disconnects);

        let activity_tracker = tracker.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(35)).await;
            activity_tracker.record_activity();
        });

        let start = Instant::now();
        let result = run_with_idle_exit(
            std::future::pending::<Result<(), std::io::Error>>(),
            &tracker,
            Duration::from_millis(70),
            move || async move {
                disconnects_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

        assert!(result.is_ok());
        assert!(
            start.elapsed() >= Duration::from_millis(90),
            "expected activity at 35ms to extend idle deadline, elapsed: {:?}",
            start.elapsed()
        );
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
    }
}
