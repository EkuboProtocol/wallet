//! One owner call's transport lifetime. Inspect `AsyncRead`, including runtime
//! prefetch buffers, rather than inferring protocol state from kernel peeks.

use anyhow::{Result, ensure};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Clone)]
pub struct OwnerCallBinding(Arc<AtomicBool>);

impl OwnerCallBinding {
    pub fn ensure_live(&self) -> Result<()> {
        ensure!(self.0.load(Ordering::Acquire), "owner call transport ended");
        Ok(())
    }

    #[must_use]
    pub fn same_call(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn cancel(&self) {
        self.0.store(false, Ordering::Release);
    }
}

pub struct OwnerCallMonitor<R> {
    reader: R,
    binding: OwnerCallBinding,
}

impl<R: AsyncRead + Unpin> OwnerCallMonitor<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            binding: OwnerCallBinding(Arc::new(AtomicBool::new(true))),
        }
    }

    #[must_use]
    pub fn binding(&self) -> OwnerCallBinding {
        self.binding.clone()
    }

    /// Run one phase, polling the real reader first on every wake and again
    /// before accepting completion. A cancelled/failed phase ends the call;
    /// successful phases may continue to the response write under the same guard.
    pub async fn run<F, T>(&mut self, operation: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let mut phase = Phase {
            binding: self.binding.clone(),
            completed: false,
            operation: Box::pin(operation),
        };
        self.binding.ensure_live()?;
        let result = poll_fn(|cx| {
            if let Err(error) = self.binding.ensure_live() {
                return Poll::Ready(Err(error));
            }
            if let Poll::Ready(error) = self.poll_departure(cx) {
                return Poll::Ready(Err(error));
            }
            match phase.operation.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    if let Poll::Ready(error) = self.poll_departure(cx) {
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(result)
                }
            }
        })
        .await;
        phase.completed = result.is_ok();
        result
    }

    fn poll_departure(&mut self, cx: &mut std::task::Context<'_>) -> Poll<anyhow::Error> {
        let mut byte = [0];
        let mut buffer = ReadBuf::new(&mut byte);
        let error = match Pin::new(&mut self.reader).poll_read(cx, &mut buffer) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                anyhow::anyhow!("owner connection closed")
            }
            Poll::Ready(Ok(())) => anyhow::anyhow!("unexpected traffic on owner connection"),
            Poll::Ready(Err(error)) => error.into(),
        };
        // Revoke before dropping the operation or allowing a caller to inspect
        // the error. Captured native authorization cannot survive this event.
        self.binding.cancel();
        Poll::Ready(error)
    }
}

impl<R> Drop for OwnerCallMonitor<R> {
    fn drop(&mut self) {
        self.binding.cancel();
    }
}

struct Phase<F> {
    binding: OwnerCallBinding,
    completed: bool,
    operation: Pin<Box<F>>,
}
impl<F> Drop for Phase<F> {
    fn drop(&mut self) {
        if !self.completed {
            self.binding.cancel();
        }
    }
}

#[cfg(test)]
#[path = "owner_call_monitor_test.rs"]
mod tests;
