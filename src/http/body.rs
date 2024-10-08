use std::{
    pin::{pin, Pin},
    task::{Context, Poll},
    time::Duration,
};

use axum::body::Body;
use bytes::{Buf, Bytes};
use futures::Stream;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use sync_wrapper::SyncWrapper;
use tokio::sync::oneshot::{self, Receiver, Sender};

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

/// Wrapper for Axum body that makes it `Sync` to be usable with Request.
/// TODO find a better way?
pub struct SyncBodyDataStream {
    inner: SyncWrapper<Body>,
}

impl SyncBodyDataStream {
    pub const fn new(body: Body) -> Self {
        Self {
            inner: SyncWrapper::new(body),
        }
    }
}

impl Stream for SyncBodyDataStream {
    type Item = Result<Bytes, axum::Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let mut pinned = pin!(self.inner.get_mut());
            match futures_util::ready!(pinned.as_mut().poll_frame(cx)?) {
                Some(frame) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(_frame) => {}
                },
                None => return Poll::Ready(None),
            }
        }
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
    E: std::string::ToString,
{
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = pin!(&mut self.inner).poll_frame(cx);

        match &poll {
            // There is still some data available
            Poll::Ready(Some(v)) => match v {
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
            Poll::Ready(None) => {
                // Make borrow checker happy
                let x = self.bytes_sent;
                self.finish(Ok(x));
            }

            // Do nothing
            Poll::Pending => {}
        }

        poll
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
    async fn test_body_stream() {
        let data = b"foobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbl\
        ahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahbla\
        hfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoob\
        arblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbla\
        blahfoobarblahblah";

        let stream = tokio_util::io::ReaderStream::new(&data[..]);
        let body = axum::body::Body::from_stream(stream);

        let (body, rx) = CountingBody::new(body);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let size = rx.await.unwrap().unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_body_full() {
        let data = vec![0; 512];
        let buf = bytes::Bytes::from_iter(data.clone());
        let body = http_body_util::Full::new(buf);

        let (body, rx) = CountingBody::new(body);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let size = rx.await.unwrap().unwrap();
        assert_eq!(size, data.len() as u64);
    }
}
