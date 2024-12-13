use std::{
    pin::{pin, Pin},
    sync::atomic::{AtomicBool, Ordering},
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};

use axum::body::Body;
use bytes::{Buf, Bytes};
use futures_util::ready;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver, Sender},
};

use super::{calc_headers_size, Error};

// Read the given body enforcing a size & time limit
pub async fn buffer_body<H: HttpBody + Send>(
    body: H,
    size_limit: usize,
    timeout: Duration,
) -> Result<Bytes, Error>
where
    <H as HttpBody>::Data: Buf + Send + Sync + 'static,
    <H as HttpBody>::Error: std::error::Error + Send + Sync + 'static,
{
    // Collect the request body up to the limit
    let body = tokio::time::timeout(timeout, Limited::new(body, size_limit).collect()).await;

    // Body reading timed out
    let Ok(body) = body else {
        return Err(Error::BodyTimedOut);
    };

    let body = body
        .map_err(|e| {
            // TODO improve the inferring somehow
            e.downcast_ref::<LengthLimitError>().map_or_else(
                || Error::BodyReadingFailed(e.to_string()),
                |_| Error::BodyTooBig,
            )
        })?
        .to_bytes();

    Ok(body)
}

pub type BodyResult = Result<u64, String>;

/// Wrapper that makes the provided body Sync
#[derive(Debug)]
pub struct SyncBody {
    inner: Mutex<Pin<Box<Body>>>,
}

impl SyncBody {
    pub fn new(inner: Body) -> Self {
        Self {
            inner: Mutex::new(Box::pin(inner)),
        }
    }
}

impl http_body::Body for SyncBody {
    type Data = Bytes;
    type Error = axum::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.lock().unwrap().as_mut().poll_frame(cx)
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.lock().unwrap().as_ref().is_end_stream()
    }

    #[inline]
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.lock().unwrap().as_ref().size_hint()
    }
}

/// Wrapper that overrides the size hint of the inner body
#[derive(Debug)]
pub struct HintBody {
    inner: http_body_util::combinators::UnsyncBoxBody<Bytes, axum::Error>,
    hint: SizeHint,
}

impl HintBody {
    pub fn new<B>(body: B, size: Option<u64>) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<axum::BoxError>,
    {
        Self {
            inner: body.map_err(axum::Error::new).boxed_unsync(),
            hint: size.map(SizeHint::with_exact).unwrap_or_default(),
        }
    }
}

impl http_body::Body for HintBody {
    type Data = Bytes;
    type Error = axum::Error;

    #[inline]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.hint.clone()
    }
}

/// Body that notifies that it has finished by sending a value over the provided channel.
/// Use AtomicBool flag to make sure we notify only once.
pub struct NotifyingBody<D, E, S: Clone + Unpin> {
    inner: Pin<Box<dyn HttpBody<Data = D, Error = E> + Send + 'static>>,
    tx: mpsc::Sender<S>,
    sig: S,
    sent: AtomicBool,
}

impl<D, E, S: Clone + Unpin> NotifyingBody<D, E, S> {
    pub fn new<B>(inner: B, tx: mpsc::Sender<S>, sig: S) -> Self
    where
        B: HttpBody<Data = D, Error = E> + Send + 'static,
        D: Buf,
    {
        Self {
            inner: Box::pin(inner),
            tx,
            sig,
            sent: AtomicBool::new(false),
        }
    }

    fn notify(&self) {
        if self
            .sent
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            == Ok(false)
        {
            let _ = self.tx.try_send(self.sig.clone()).is_ok();
        }
    }
}

impl<D, E, S: Clone + Unpin> HttpBody for NotifyingBody<D, E, S>
where
    D: Buf,
    E: ToString,
{
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = ready!(pin!(&mut self.inner).poll_frame(cx));
        if poll.is_none() {
            self.notify();
        }

        Poll::Ready(poll)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        let end = self.inner.is_end_stream();
        if end {
            self.notify();
        }

        end
    }
}

// Body that counts the bytes streamed
pub struct CountingBody<D, E> {
    inner: Pin<Box<dyn HttpBody<Data = D, Error = E> + Send + 'static>>,
    tx: Option<Sender<BodyResult>>,
    expected_size: Option<u64>,
    bytes_sent: u64,
}

impl<D, E> CountingBody<D, E> {
    pub fn new<B>(inner: B) -> (Self, Receiver<BodyResult>)
    where
        B: HttpBody<Data = D, Error = E> + Send + 'static,
        D: Buf,
    {
        let expected_size = inner.size_hint().exact();
        let (tx, rx) = oneshot::channel();

        let mut body = Self {
            inner: Box::pin(inner),
            tx: Some(tx),
            expected_size,
            bytes_sent: 0,
        };

        // If the size is known and zero - finish now,
        // otherwise it won't be called anywhere else
        if expected_size == Some(0) {
            body.finish(Ok(0));
        }

        (body, rx)
    }

    pub fn finish(&mut self, res: Result<u64, String>) {
        if let Some(v) = self.tx.take() {
            let _ = v.send(res);
        }
    }
}

impl<D, E> HttpBody for CountingBody<D, E>
where
    D: Buf,
    E: ToString,
{
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = ready!(pin!(&mut self.inner).poll_frame(cx));

        match &poll {
            // There is still some data available
            Some(v) => match v {
                Ok(buf) => {
                    // Normal data frame
                    if buf.is_data() {
                        self.bytes_sent += buf.data_ref().unwrap().remaining() as u64;
                    } else if buf.is_trailers() {
                        // Trailers are very uncommon, for the sake of completeness
                        self.bytes_sent += calc_headers_size(buf.trailers_ref().unwrap()) as u64;
                    }

                    // Check if we already got what was expected
                    if Some(self.bytes_sent) >= self.expected_size {
                        // Make borrow checker happy
                        let x = self.bytes_sent;
                        self.finish(Ok(x));
                    }
                }

                // Error occured
                Err(e) => {
                    self.finish(Err(e.to_string()));
                }
            },

            // Nothing left
            None => {
                // Make borrow checker happy
                let x = self.bytes_sent;
                self.finish(Ok(x));
            }
        }

        Poll::Ready(poll)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_counting_body_stream() {
        let data = b"foobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbl\
        ahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahbla\
        hfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoob\
        arblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbla\
        blahfoobarblahblah";

        let stream = tokio_util::io::ReaderStream::new(&data[..]);
        let body = Body::from_stream(stream);

        let (body, rx) = CountingBody::new(body);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let size = rx.await.unwrap().unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_counting_body_full() {
        let data = vec![0; 512];
        let buf = Bytes::from_iter(data.clone());
        let body = http_body_util::Full::new(buf);

        let (body, rx) = CountingBody::new(body);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let size = rx.await.unwrap().unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_notifying_body() {
        let data = b"foobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbl\
        ahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahbla\
        hfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoob\
        arblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbla\
        blahfoobarblahblah";

        let stream = tokio_util::io::ReaderStream::new(&data[..]);
        let body = Body::from_stream(stream);

        let sig = 357;
        let (tx, mut rx) = mpsc::channel(10);
        let body = NotifyingBody::new(body, tx, sig);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Make sure we're notified
        assert_eq!(sig, rx.recv().await.unwrap());
    }
}
