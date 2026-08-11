use anyhow::{Context, Result};
use fs2::FileExt as _;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    thread::JoinHandle,
    time::Duration,
};

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
    pub fn acquire(data_dir: &Path, activations: Sender<()>) -> Result<InstanceOutcome> {
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

#[cfg(unix)]
fn activate_existing(data_dir: &Path) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::net::UnixStream;

    let path = data_dir.join("activate.sock");
    let mut last_error = None;
    for _ in 0..20 {
        match UnixStream::connect(&path) {
            Ok(mut stream) => {
                stream.write_all(b"activate")?;
                return Ok(());
            }
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

#[cfg(not(unix))]
fn activate_existing(_data_dir: &Path) -> Result<()> {
    use interprocess::local_socket::{GenericNamespaced, Stream, prelude::*};
    use std::io::Write as _;

    let pipe_name = activation_pipe_name(_data_dir);
    let name = pipe_name.to_ns_name::<GenericNamespaced>()?;
    let mut stream = Stream::connect(name).context("the running wallet could not be activated")?;
    stream.write_all(b"activate")?;
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
