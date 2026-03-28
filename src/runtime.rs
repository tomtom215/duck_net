use std::future::Future;
use std::sync::LazyLock;

use tokio::runtime::Runtime;

/// Shared tokio runtime for all async operations (DNS, SFTP).
/// Runs on a dedicated thread to avoid "cannot start a runtime from within a runtime" panics
/// when DuckDB is hosted inside another async runtime (e.g., Python with asyncio).
static RT: LazyLock<Runtime> = LazyLock::new(|| {
    std::thread::Builder::new()
        .name("duck_net-async".into())
        .spawn(|| {})
        .ok();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
});

/// Run an async future to completion, safely handling the case where
/// we may already be inside a tokio runtime.
pub fn block_on<F: Future + Send>(future: F) -> F::Output
where
    F::Output: Send,
{
    // If we're already in a tokio runtime, use spawn_blocking + a new current-thread runtime
    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
        // We're inside an existing runtime - use a blocking thread
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create nested runtime");
                rt.block_on(future)
            }).join().expect("Async task panicked")
        })
    } else {
        // No runtime, use our shared one
        RT.block_on(future)
    }
}
