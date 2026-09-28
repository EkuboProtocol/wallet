use anyhow::{Context, Result};
use fs2::FileExt as _;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;

pub enum InstanceOutcome {
    Primary(SingleInstance),
    ActivatedExisting,
}

pub struct SingleInstance {
    lock: File,
    shutdown: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl SingleInstance {
    /// `activations` is unbounded and non-blocking on purpose: the listener
    /// threads below send from outside any runtime, and the receiving end has
    /// to stay a cancellable future rather than a parked blocking task, or the
    /// Tokio join at quit would have to wait it out. See `join_tokio_runtime`.
    pub fn acquire(data_dir: &Path, activations: UnboundedSender<()>) -> Result<InstanceOutcome> {
        std::fs::create_dir_all(data_dir)?;
        let lock_path = data_dir.join("application.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        if lock.try_lock_exclusive().is_err() {
            activate_existing(data_dir)?;
            return Ok(InstanceOutcome::ActivatedExisting);
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        #[cfg(unix)]
        {
            use std::os::unix::{fs::PermissionsExt as _, net::UnixListener};

            let socket_path = data_dir.join("activate.sock");
            if socket_path.exists() {
                std::fs::remove_file(&socket_path)
                    .with_context(|| format!("failed to remove stale {}", socket_path.display()))?;
            }
            let listener = UnixListener::bind(&socket_path)
                .with_context(|| format!("failed to bind {}", socket_path.display()))?;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let stopped = shutdown.clone();
            let thread = std::thread::spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((_stream, _address)) => {
                            let _ = activations.send(());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(75));
                        }
                        Err(error) if one_connection_failed(&error) => {}
                        Err(_) => break,
                    }
                }
            });
            Ok(InstanceOutcome::Primary(Self {
                lock,
                shutdown,
                listener: Some(thread),
                socket_path,
            }))
        }

        #[cfg(not(unix))]
        {
            use interprocess::local_socket::{
                GenericNamespaced, ListenerNonblockingMode, ListenerOptions, prelude::*,
            };

            let pipe_name = activation_pipe_name(data_dir);
            let name = pipe_name.to_ns_name::<GenericNamespaced>()?;
            let listener = ListenerOptions::new()
                .name(name)
                .nonblocking(ListenerNonblockingMode::Accept)
                .create_sync()
                .context("failed to create the current-user activation pipe")?;
            let stopped = shutdown.clone();
            let thread = std::thread::spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok(_stream) => {
                            let _ = activations.send(());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(75));
                        }
                        Err(error) if one_connection_failed(&error) => {}
                        Err(_) => break,
                    }
                }
            });
            Ok(InstanceOutcome::Primary(Self {
                lock,
                shutdown,
                listener: Some(thread),
            }))
        }
    }
}

/// An accept that failed for one client, not for the listener. Neither is a
/// reason to stop listening: that would leave every later launch connecting
/// to a primary that never raises its window again.
fn one_connection_failed(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted
    )
}

/// Connecting is the whole activation: the primary fires on accept and drops
/// the stream unread, which is also what every earlier release does.
///
/// There used to be an `activate` payload written after connecting. Nothing
/// ever read it, and when the primary accepted and hung up between the connect
/// and the write, the write failed with `EPIPE` — reporting a failed launch for
/// an activation that had already been delivered. macOS lost that race often
/// enough to redden CI.
#[cfg(unix)]
fn activate_existing(data_dir: &Path) -> Result<()> {
    use std::os::unix::net::UnixStream;

    let path = data_dir.join("activate.sock");
    let mut last_error = None;
    for _ in 0..20 {
        match UnixStream::connect(&path) {
            // A queued connection survives this end closing, so the primary
            // still accepts it, and still activates, after we have gone.
            Ok(_stream) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(last_error.map_or_else(
        || anyhow::anyhow!("the running wallet could not be activated"),
        anyhow::Error::from,
    ))
}

/// How long a second launch holds its pipe open for the primary to accept it.
///
/// The primary polls on a 75 ms cycle; this only bounds how long a launch
/// waits on a primary that is alive enough to hold the lock but not accepting.
#[cfg(not(unix))]
const ACTIVATION_HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);

/// Same protocol as Unix — connecting is the activation — but a named pipe
/// does not queue a connection the way a socket does. A client that has
/// already closed when the primary gets to `accept` leaves a dead instance
/// that interprocess discards without handing it out, so the activation would
/// silently vanish. Hold the pipe until the primary hangs up on it; a hang-up
/// reads as end of file.
#[cfg(not(unix))]
fn activate_existing(data_dir: &Path) -> Result<()> {
    use interprocess::local_socket::{GenericNamespaced, Stream, prelude::*};
    use std::io::Read as _;

    let pipe_name = activation_pipe_name(data_dir);
    let name = pipe_name.to_ns_name::<GenericNamespaced>()?;
    let mut stream = Stream::connect(name).context("the running wallet could not be activated")?;
    let (hung_up, accepted) = std::sync::mpsc::channel();
    // A thread rather than a read timeout, which a named pipe does not offer.
    // If the wait runs out, the thread is left blocked and goes with the
    // process, which is about to exit anyway.
    std::thread::spawn(move || {
        let _ = stream.read(&mut [0; 1]);
        let _ = hung_up.send(());
    });
    let _ = accepted.recv_timeout(ACTIVATION_HANDOFF_TIMEOUT);
    Ok(())
}

#[cfg(not(unix))]
fn activation_pipe_name(data_dir: &Path) -> String {
    use std::hash::{Hash as _, Hasher as _};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data_dir.hash(&mut hasher);
    format!("org.ekubo.wallet.activate.{:016x}", hasher.finish())
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        #[cfg(unix)]
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
        let _ = self.lock.unlock();
    }
}

#[cfg(all(test, unix))]
#[path = "single_instance_test.rs"]
mod tests;
