use async_std::net::driver::Watcher;
use async_std::task::Context;
use futures::{Poll, Stream};
use std::borrow::Borrow;
use std::io::Result;
use std::os::raw::c_int;
use std::pin::Pin;

pub struct Signals {
    watcher: Watcher<signal_hook::iterator::Signals>,
}

impl Signals {
    pub fn new<I, S>(signals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Borrow<c_int>,
    {
        let s = signal_hook::iterator::Signals::new(signals).expect("listen signals");

        Signals {
            watcher: Watcher::new(s),
        }
    }
}

impl Stream for Signals {
    type Item = Result<Vec<c_int>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let r = self.watcher.poll_read_with(cx, |signals| {
            if !signals.is_closed() {
                let signals: Vec<c_int> = signals.pending().collect();
                Ok(Some(signals))
            } else {
                Ok(None)
            }
        });
        match r {
            Poll::Ready(s) => Poll::Ready(s.transpose()),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use futures::StreamExt;

    #[test]
    fn test_signal() {
        let mut signals = Signals::new(&[signal_hook::SIGUSR1]);
        unsafe {
            libc::kill(libc::getpid(), signal_hook::SIGUSR1);
        }
        task::block_on(async move {
            for sig in signals.next().await {
                let sigs = sig.unwrap();
                assert_eq!(&sigs, &[signal_hook::SIGUSR1])
            }
        })
    }
}
