// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::Runtime;

/// Shared tokio runtime for all async operations (DNS, SFTP, gRPC, etc.).
///
/// Stored in a `OnceLock` so that initialisation can be attempted explicitly
/// during extension load (via [`init`]) and any OS-level failure is surfaced as
/// a DuckDB error rather than an unrecoverable process abort.
///
/// The runtime is a `current_thread` runtime (single-threaded event loop) to
/// avoid spawning background threads that persist past the extension lifetime
/// and to stay compatible with DuckDB's single-threaded query execution model.
static RT: OnceLock<Runtime> = OnceLock::new();

/// Initialise the shared tokio runtime.
///
/// Must be called during `register_all` before any async operation is
/// attempted.  Returns an error if the OS refuses to allocate threads or
/// I/O resources.  Calling this more than once is safe — subsequent calls
/// are no-ops.
pub fn init() -> Result<(), String> {
    if RT.get().is_some() {
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            format!(
                "duck_net: failed to create tokio runtime: {e}. \
                 This usually indicates the OS is out of resources (threads, file descriptors). \
                 Check system limits (ulimit -n, /proc/sys/kernel/threads-max)."
            )
        })?;
    // `set` only fails if another thread beat us to it; in that case the
    // existing runtime is fine, so we discard the new one.
    let _ = RT.set(rt);
    Ok(())
}

/// Run an async future to completion on the shared runtime.
///
/// Falls back to a temporary per-call runtime when already executing inside
/// an existing async context (e.g., Python asyncio, tests) to avoid the
/// "nested runtime" panic.
///
/// # Panics
/// Panics if `init()` was never called.  This is a programming error —
/// `init()` is always called by `register_all` before any protocol function
/// can be invoked, so this should never trigger in practice.
pub fn block_on<F: Future + Send>(future: F) -> F::Output
where
    F::Output: Send,
{
    // If we're already inside a tokio runtime (e.g. integration test or
    // a Python async host), create a throw-away current-thread runtime on a
    // blocking thread to avoid the "start a runtime inside a runtime" error.
    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
        return std::thread::scope(|s| {
            s.spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create nested runtime")
                    .block_on(future)
            })
            .join()
            .expect("Async task thread panicked")
        });
    }

    RT.get()
        .expect(
            "duck_net: tokio runtime used before initialisation. \
             This is a bug — please file an issue at https://github.com/tomtom215/duck_net",
        )
        .block_on(future)
}
