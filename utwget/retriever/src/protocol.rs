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
