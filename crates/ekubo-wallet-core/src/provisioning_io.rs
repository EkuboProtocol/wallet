//! Run the shared blocking codec over native asynchronous transports. Authentication
//! must precede this adapter; it supplies only deadline and cancellation behavior.
use std::{
    future::Future as _,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::{
    io::SyncIoBridge,
    sync::{CancellationToken, WaitForCancellationFutureOwned},
};

pub struct CancelTransfer(CancellationToken);
impl Drop for CancelTransfer {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub struct DeadlineStream<S> {
    stream: S,
    deadline: Pin<Box<tokio::time::Sleep>>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    failure: Option<io::ErrorKind>,
}

/// Construct inside the host runtime, then move the bridge into `spawn_blocking`.
/// Keep the guard on the awaiting task: dropping it wakes pending native I/O.
pub fn bridge<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    duration: Duration,
) -> (SyncIoBridge<DeadlineStream<S>>, CancelTransfer) {
    let cancel = CancellationToken::new();
    let stream = DeadlineStream {
        stream,
        deadline: Box::pin(tokio::time::sleep(duration)),
        cancelled: Box::pin(cancel.clone().cancelled_owned()),
        failure: None,
    };
    (SyncIoBridge::new(stream), CancelTransfer(cancel))
}

impl<S> DeadlineStream<S> {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.failure.is_none() && self.cancelled.as_mut().poll(cx).is_ready() {
            self.failure = Some(io::ErrorKind::ConnectionAborted);
        }
        if self.failure.is_none() && self.deadline.as_mut().poll(cx).is_ready() {
            self.failure = Some(io::ErrorKind::TimedOut);
        }
        match self.failure {
            // Never use Interrupted: Read::read_exact retries that indefinitely.
            Some(kind) => Err(io::Error::new(kind, "provisioning transfer ended")),
            None => Ok(()),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DeadlineStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.stream).poll_read(cx, output)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for DeadlineStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.stream).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "provisioning_io_test.rs"]
mod tests;
