use std::io::{self, Write};
use std::time::Duration;

use ut_core::url::ParsedUrl;
use ut_core::WgetError;
use ut_progress::ProgressDisplay;

use crate::types::{
    BodyResult, RequestOptions, Protocol, ProtocolState, ResponseMeta, RetrieveError,
};

pub struct HttpProtocolAdapter;

impl Protocol for HttpProtocolAdapter {
    fn request(
        &self,
        _url: &ParsedUrl,
        _opts: &RequestOptions,
        _state: &mut ProtocolState,
    ) -> Result<ResponseMeta, RetrieveError> {
        Err(RetrieveError::Protocol(WgetError::Other(
            "HTTP adapter requires a live connection; use Retriever directly".into(),
        )))
    }

    fn read_body(
        &self,
        _response: &mut ResponseMeta,
        _output: &mut dyn Write,
        _state: &mut ProtocolState,
        _progress: Option<&mut dyn ProgressDisplay>,
    ) -> Result<BodyResult, RetrieveError> {
        Err(RetrieveError::Protocol(WgetError::Other(
            "HTTP adapter requires a live connection; use Retriever directly".into(),
        )))
    }

    fn supports_resume(&self) -> bool {
        true
    }

    fn supports_conditional(&self) -> bool {
        true
    }

    fn connection_reusable(&self) -> bool {
        true
    }
}

pub struct FtpProtocolAdapter;

impl Protocol for FtpProtocolAdapter {
    fn request(
        &self,
        _url: &ParsedUrl,
        _opts: &RequestOptions,
        _state: &mut ProtocolState,
    ) -> Result<ResponseMeta, RetrieveError> {
        Err(RetrieveError::Protocol(WgetError::Other(
            "FTP adapter requires a live connection; use Retriever directly".into(),
        )))
    }

    fn read_body(
        &self,
        _response: &mut ResponseMeta,
        _output: &mut dyn Write,
        _state: &mut ProtocolState,
        _progress: Option<&mut dyn ProgressDisplay>,
    ) -> Result<BodyResult, RetrieveError> {
        Err(RetrieveError::Protocol(WgetError::Other(
            "FTP adapter requires a live connection; use Retriever directly".into(),
        )))
    }

    fn supports_resume(&self) -> bool {
        true
    }

    fn supports_conditional(&self) -> bool {
        false
    }

    fn connection_reusable(&self) -> bool {
        false
    }
}

pub trait RateLimitedWrite: Write {
    fn limit(&mut self, bytes: usize);
}

pub struct RateLimitedWriter<'a, W: Write> {
    inner: &'a mut W,
    bytes_per_second: u64,
    bucket: u64,
    max_bucket: u64,
    last_refill: std::time::Instant,
}

pub struct OwnedRateLimitedWriter {
    inner: Box<dyn Write>,
    bytes_per_second: u64,
    bucket: u64,
    max_bucket: u64,
    last_refill: std::time::Instant,
}

impl<'a, W: Write> RateLimitedWriter<'a, W> {
    pub fn new(inner: &'a mut W, bytes_per_second: u64) -> Self {
        let bps = if bytes_per_second == 0 { u64::MAX } else { bytes_per_second };
        RateLimitedWriter {
            inner,
            bytes_per_second: bps,
            bucket: bps,
            max_bucket: bps,
            last_refill: std::time::Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;
        let refill = (elapsed.as_secs_f64() * self.bytes_per_second as f64) as u64;
        self.bucket = (self.bucket + refill).min(self.max_bucket);
    }
}

impl OwnedRateLimitedWriter {
    pub fn owned(inner: Box<dyn Write>, bytes_per_second: u64) -> Self {
        let bps = if bytes_per_second == 0 { u64::MAX } else { bytes_per_second };
        OwnedRateLimitedWriter {
            inner,
            bytes_per_second: bps,
            bucket: bps,
            max_bucket: bps,
            last_refill: std::time::Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;
        let refill = (elapsed.as_secs_f64() * self.bytes_per_second as f64) as u64;
        self.bucket = (self.bucket + refill).min(self.max_bucket);
    }
}

impl<'a, W: Write> Write for RateLimitedWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes_per_second == u64::MAX {
            return self.inner.write(buf);
        }

        let mut written = 0usize;
        while written < buf.len() {
            self.refill();
            let available = self.bucket.min((buf.len() - written) as u64) as usize;
            if available == 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let n = self.inner.write(&buf[written..written + available])?;
            if n == 0 {
                break;
            }
            written += n;
            self.bucket = self.bucket.saturating_sub(n as u64);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Write for OwnedRateLimitedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes_per_second == u64::MAX {
            return self.inner.write(buf);
        }

        let mut written = 0usize;
        while written < buf.len() {
            self.refill();
            let available = self.bucket.min((buf.len() - written) as u64) as usize;
            if available == 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let n = self.inner.write(&buf[written..written + available])?;
            if n == 0 {
                break;
            }
            written += n;
            self.bucket = self.bucket.saturating_sub(n as u64);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct ProgressWriter<'a, W: Write, P: ProgressDisplay> {
    inner: W,
    progress: &'a mut P,
    total_written: u64,
}

impl<'a, W: Write, P: ProgressDisplay> ProgressWriter<'a, W, P> {
    pub fn new(inner: W, progress: &'a mut P) -> Self {
        ProgressWriter {
            inner,
            progress,
            total_written: 0,
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.total_written
    }
}
