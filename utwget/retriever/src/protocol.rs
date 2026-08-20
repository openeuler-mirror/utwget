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
