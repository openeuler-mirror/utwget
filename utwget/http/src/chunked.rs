//! HTTP Chunked Transfer Encoding support.
//!
//! This module provides a reader for HTTP response bodies using chunked
//! transfer encoding as specified in RFC 7230 Section 4.1.
//!
//! # Chunked Transfer Encoding
//!
//! When a server uses chunked encoding, the response body is sent as a series
//! of chunks, each prefixed with its size in hexadecimal. The body is terminated
//! by a zero-sized chunk. This allows the server to send dynamically generated
//! content without knowing the total size in advance.
//!
//! # Example
//!
//! ```ignore
//! use utwget_http::chunked::ChunkedReader;
//! use std::io::Cursor;
//!
//! // HTTP chunked response body: "5\r\nhello\r\n0\r\n\r\n"
//! let data = b"5\r\nhello\r\n0\r\n\r\n";
//! let mut cursor = Cursor::new(&data[..]);
//! let mut reader = ChunkedReader::new(&mut cursor);
//!
//! // Read all chunks
//! let mut output = Vec::new();
//! let total = reader.read_to_end(&mut output).unwrap();
//! assert_eq!(output, b"hello");
//! ```

use std::io::{self, Read, Write};

/// Internal state machine for chunk parsing.
enum ChunkState {
    /// Waiting to read the next chunk size line.
    ReadSize,
    /// Currently reading chunk data with `remaining` bytes left.
    ReadData { remaining: usize },
    /// Reading trailer headers after the final zero-sized chunk.
    ReadTrailer,
    /// All chunks have been read; no more data available.
    Done,
}

/// Reader for HTTP chunked transfer-encoded response bodies.
///
/// Wraps an underlying transport and parses chunk boundaries, returning
/// only the actual chunk data to the caller.
///
/// # Example
///
/// ```ignore
/// let mut reader = ChunkedReader::new(&mut transport);
///
/// // Iterate over chunks
/// while let Some(chunk) = reader.read_next_chunk().unwrap() {
///     // process chunk
/// }
///
/// // Or read all at once
/// let mut output = Vec::new();
/// reader.read_to_end(&mut output).unwrap();
/// ```
pub struct ChunkedReader<'a, T> {
    /// The underlying transport reader.
    transport: &'a mut T,
    /// Buffer for partially read data.
    buffer: Vec<u8>,
    /// Current state of the chunk parser.
    state: ChunkState,
}

impl<'a, T: Read> ChunkedReader<'a, T> {
    /// Creates a new `ChunkedReader` wrapping the given transport.
    ///
    /// # Arguments
    ///
    /// * `transport` - The underlying reader providing the chunked response body.
    ///
    /// # Returns
    ///
    /// A new `ChunkedReader` ready to parse chunks.
    pub fn new(transport: &'a mut T) -> Self {
        ChunkedReader {
            transport,
            buffer: Vec::new(),
            state: ChunkState::ReadSize,
        }
    }

    /// Ensures the internal buffer contains at least `needed` bytes.
    ///
    /// Reads more data from the transport if necessary.
    ///
    /// # Arguments
    ///
    /// * `needed` - The minimum number of bytes needed in the buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport ends before enough data is available.
    fn ensure_buffer(&mut self, needed: usize) -> io::Result<()> {
        if self.buffer.len() < needed {
            let mut tmp = [0u8; 8192];
            loop {
                let n = self.transport.read(&mut tmp)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF in chunked transfer",
                    ));
                }
                self.buffer.extend_from_slice(&tmp[..n]);
                if self.buffer.len() >= needed {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Reads a single line terminated by CRLF from the transport.
    ///
    /// # Returns
    ///
    /// The line content without the trailing CRLF.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport ends before a complete line is found.
    fn read_line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(pos) = self.buffer.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buffer[..pos].to_vec();
                self.buffer.drain(..pos + 2);
                return Ok(line);
            }

            let mut tmp = [0u8; 8192];
            let n = self.transport.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF reading chunk line",
                ));
            }
            self.buffer.extend_from_slice(&tmp[..n]);
        }
    }

    /// Parses a chunk size line (hexadecimal number with optional extensions).
    ///
    /// The line may contain chunk extensions after a semicolon, which are ignored.
    ///
    /// # Arguments
    ///
    /// * `line` - The chunk size line (e.g., `"5"`, `"1a;name=value"`).
    ///
    /// # Returns
    ///
    /// The parsed chunk size as a number of bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the line is not valid hexadecimal.
    fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
        let line_str = std::str::from_utf8(line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size not valid utf8"))?;

        let hex_str = line_str
            .split(';')
            .next()
            .unwrap_or("")
            .trim();

        usize::from_str_radix(hex_str, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {}", hex_str),
            )
        })
    }

    /// Reads the next chunk of data from the response body.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` - The next chunk's data.
    /// - `Ok(None)` - End of chunked body (zero-sized chunk received).
    ///
    /// # Errors
    ///
    /// Returns an error if the chunked encoding is malformed or an I/O error occurs.
    pub fn read_next_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            match &self.state {
                ChunkState::ReadSize => {
                    let line = self.read_line()?;
                    if line.is_empty() {
                        continue;
                    }
                    let size = Self::parse_chunk_size(&line)?;
                    if size == 0 {
                        self.state = ChunkState::ReadTrailer;
                        continue;
                    }
                    self.state = ChunkState::ReadData { remaining: size };
                }
                ChunkState::ReadData { remaining } => {
                    let remaining = *remaining;
                    if self.buffer.len() >= remaining + 2 {
                        let data: Vec<u8> = self.buffer[..remaining].to_vec();
                        self.buffer.drain(..remaining + 2);
                        self.state = ChunkState::ReadSize;
                        return Ok(Some(data));
                    }

                    let needed = remaining + 2;
                    self.ensure_buffer(needed)?;
                }
                ChunkState::ReadTrailer => {
                    let line = self.read_line()?;
                    if line.is_empty() {
                        self.state = ChunkState::Done;
                        return Ok(None);
                    }
                }
                ChunkState::Done => {
                    return Ok(None);
                }
            }
        }
    }

    /// Reads all remaining chunks and writes them to the output.
    ///
    /// This is a convenience method for reading the entire chunked body
    /// in one operation.
    ///
    /// # Arguments
    ///
    /// * `output` - The writer to receive the decoded body data.
    ///
    /// # Returns
    ///
    /// The total number of bytes written to the output.
    ///
    /// # Errors
    ///
    /// Returns an error if any chunk is malformed or an I/O error occurs.
    pub fn read_to_end<W: Write>(&mut self, output: &mut W) -> io::Result<u64> {
        let mut total = 0u64;
        while let Some(chunk) = self.read_next_chunk()? {
            output.write_all(&chunk)?;
            total += chunk.len() as u64;
        }
        Ok(total)
    }
}
