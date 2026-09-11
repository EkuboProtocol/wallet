//! A connected, installer-owned Unix stream with one absolute I/O deadline.
use anyhow::{Result, ensure};
use rustix::net::{AddressFamily, SocketType, sockopt};
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

pub(super) struct InstallerStream {
    stream: UnixStream,
    deadline: Instant,
}

pub(super) struct CancelStream(UnixStream);
impl Drop for CancelStream {
    fn drop(&mut self) {
        // Shutdown the same socket object, including a blocking worker's cloned
        // handle. Dropping the async waiter alone would leave its read hanging.
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

impl InstallerStream {
    pub(super) fn new(
        fd: OwnedFd,
        process_id: u32,
        duration: Duration,
    ) -> Result<(Self, CancelStream)> {
        validate_peer(&fd, 0, process_id)?;
        Self::with_deadline(UnixStream::from(fd), duration)
    }

    fn with_deadline(stream: UnixStream, duration: Duration) -> Result<(Self, CancelStream)> {
        stream.set_nonblocking(false)?;
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| anyhow::anyhow!("invalid provisioning deadline"))?;
        let cancel = CancelStream(stream.try_clone()?);
        Ok((Self { stream, deadline }, cancel))
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "provisioning deadline expired"))
    }
}

fn validate_peer(fd: &OwnedFd, installer_uid: u32, process_id: u32) -> Result<()> {
    ensure!(
        sockopt::socket_domain(fd)? == AddressFamily::UNIX,
        "provisioning requires a Unix socket"
    );
    ensure!(
        sockopt::socket_type(fd)? == SocketType::STREAM,
        "provisioning requires a stream socket"
    );
    let peer = sockopt::socket_peercred(fd)?;
    ensure!(
        peer.uid.as_raw() == installer_uid && u32::try_from(peer.pid.as_raw_pid())? == process_id,
        "provisioning socket is not owned by the authenticated installer"
    );
    Ok(())
}

impl Read for InstallerStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(output)
    }
}
impl Write for InstallerStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(input)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

#[cfg(test)]
#[path = "linux_provisioning_io_test.rs"]
mod tests;
