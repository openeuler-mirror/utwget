use std::io::{self, Write};
use std::time::Duration;

use ut_progress::ProgressDisplay;

pub trait RateLimitedWrite: Write {
    fn limit(&mut self, bytes: usize);
}

/// Token bucket shared by [`RateLimitedWriter`] and
/// [`OwnedRateLimitedWriter`] — the refill logic was previously duplicated
/// verbatim in both structs (arch 3.3.5).
struct TokenBucket {
    bytes_per_second: u64,
    bucket: u64,
    max_bucket: u64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(bytes_per_second: u64) -> Self {
        let bps = if bytes_per_second == 0 { u64::MAX } else { bytes_per_second };
        TokenBucket {
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

    fn take(&mut self, want: usize) -> usize {
        self.refill();
        let available = self.bucket.min(want as u64) as usize;
        self.bucket = self.bucket.saturating_sub(available as u64);
        available
    }

    fn unlimited(&self) -> bool {
        self.bytes_per_second == u64::MAX
    }
}

pub struct RateLimitedWriter<'a, W: Write> {
    inner: &'a mut W,
    bucket: TokenBucket,
}

pub struct OwnedRateLimitedWriter {
    inner: Box<dyn Write>,
    bucket: TokenBucket,
}

impl<'a, W: Write> RateLimitedWriter<'a, W> {
    pub fn new(inner: &'a mut W, bytes_per_second: u64) -> Self {
        RateLimitedWriter {
            inner,
            bucket: TokenBucket::new(bytes_per_second),
        }
    }
}

impl OwnedRateLimitedWriter {
    pub fn owned(inner: Box<dyn Write>, bytes_per_second: u64) -> Self {
        OwnedRateLimitedWriter {
            inner,
            bucket: TokenBucket::new(bytes_per_second),
        }
    }
}

impl<'a, W: Write> Write for RateLimitedWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bucket.unlimited() {
            return self.inner.write(buf);
        }

        let mut written = 0usize;
        while written < buf.len() {
            let available = self.bucket.take(buf.len() - written);
            if available == 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let n = self.inner.write(&buf[written..written + available])?;
            if n == 0 {
                break;
            }
            written += n;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Write for OwnedRateLimitedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bucket.unlimited() {
            return self.inner.write(buf);
        }

        let mut written = 0usize;
        while written < buf.len() {
            let available = self.bucket.take(buf.len() - written);
            if available == 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let n = self.inner.write(&buf[written..written + available])?;
            if n == 0 {
                break;
            }
            written += n;
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
    /// Start time for elapsed-time computation. Must be captured at
    /// construction, NOT computed via `Instant::now().elapsed()` (which
    /// is always zero — the bug fixed by this field).
    start: std::time::Instant,
}

impl<'a, W: Write, P: ProgressDisplay> ProgressWriter<'a, W, P> {
    pub fn new(inner: W, progress: &'a mut P) -> Self {
        ProgressWriter {
            inner,
            progress,
            total_written: 0,
            start: std::time::Instant::now(),
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.total_written
    }
}

impl<'a, W: Write, P: ProgressDisplay> Write for ProgressWriter<'a, W, P> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.total_written += n as u64;
        let elapsed = self.start.elapsed();
        self.progress.update(self.total_written, elapsed);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn apply_rate_limit<W: Write + 'static>(writer: W, limit: Option<u64>) -> Box<dyn Write> {
    match limit {
        Some(bps) if bps > 0 => {
            let writer = Box::new(writer);
            Box::new(OwnedRateLimitedWriter::owned(writer, bps))
        }
        _ => Box::new(writer),
    }
}
