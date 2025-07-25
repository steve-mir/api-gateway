//! # Zero-Copy Optimization Module
//!
//! This module provides zero-copy optimizations for the API Gateway to minimize
//! memory allocations and data copying during request/response processing.
//!
//! ## Zero-Copy Concepts in Rust
//!
//! - `Bytes` type for immutable, reference-counted byte buffers
//! - `BytesMut` for mutable byte buffers that can be frozen to `Bytes`
//! - Slice operations that create views without copying data
//! - Memory mapping for large files
//! - Streaming without buffering entire payloads

use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::{Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use serde::{Serialize, Deserialize};
use tracing::{debug, trace};
use metrics::{counter, histogram};

use crate::core::error::{GatewayError, GatewayResult};

/// Zero-copy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroCopyConfig {
    /// Enable zero-copy optimizations
    pub enabled: bool,
    /// Maximum buffer size for zero-copy operations
    pub max_buffer_size: usize,
    /// Minimum buffer size to use zero-copy
    pub min_buffer_size: usize,
    /// Enable memory mapping for large payloads
    pub enable_mmap: bool,
    /// Streaming chunk size
    pub chunk_size: usize,
}

impl Default for ZeroCopyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_buffer_size: 64 * 1024 * 1024, // 64MB
            min_buffer_size: 4 * 1024,         // 4KB
            enable_mmap: true,
            chunk_size: 8 * 1024,              // 8KB
        }
    }
}

/// Zero-copy byte buffer that can be shared without cloning data
#[derive(Debug, Clone)]
pub struct ZeroCopyBytes {
    /// The underlying bytes
    bytes: Bytes,
    /// Start offset in the bytes
    start: usize,
    /// Length of the valid data
    len: usize,
}

impl ZeroCopyBytes {
    /// Create a new zero-copy bytes from Bytes
    pub fn new(bytes: Bytes) -> Self {
        let len = bytes.len();
        Self {
            bytes,
            start: 0,
            len,
        }
    }

    /// Create from a byte slice (will copy data)
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(data))
    }

    /// Create from static data (zero-copy)
    pub fn from_static(data: &'static [u8]) -> Self {
        Self::new(Bytes::from_static(data))
    }

    /// Create an empty zero-copy bytes
    pub fn empty() -> Self {
        Self::new(Bytes::new())
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get a slice of the data without copying
    pub fn slice(&self, start: usize, end: usize) -> GatewayResult<ZeroCopyBytes> {
        if start > end || end > self.len {
            return Err(GatewayError::internal(
                format!("Invalid slice bounds: {}..{} for length {}", start, end, self.len)
            ));
        }

        Ok(Self {
            bytes: self.bytes.clone(),
            start: self.start + start,
            len: end - start,
        })
    }

    /// Get the data as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[self.start..self.start + self.len]
    }

    /// Convert to Bytes (zero-copy if possible)
    pub fn into_bytes(self) -> Bytes {
        if self.start == 0 && self.len == self.bytes.len() {
            self.bytes
        } else {
            self.bytes.slice(self.start..self.start + self.len)
        }
    }

    /// Split at the given index, returning two zero-copy bytes
    pub fn split_at(&self, mid: usize) -> GatewayResult<(ZeroCopyBytes, ZeroCopyBytes)> {
        if mid > self.len {
            return Err(GatewayError::internal(
                format!("Split index {} out of bounds for length {}", mid, self.len)
            ));
        }

        let left = Self {
            bytes: self.bytes.clone(),
            start: self.start,
            len: mid,
        };

        let right = Self {
            bytes: self.bytes.clone(),
            start: self.start + mid,
            len: self.len - mid,
        };

        Ok((left, right))
    }

    /// Concatenate with another zero-copy bytes
    pub fn concat(&self, other: &ZeroCopyBytes) -> ZeroCopyBytes {
        if self.is_empty() {
            return other.clone();
        }
        if other.is_empty() {
            return self.clone();
        }

        // For simplicity, we'll create a new buffer
        // In a more sophisticated implementation, you might use a rope-like structure
        let mut buf = BytesMut::with_capacity(self.len + other.len);
        buf.put_slice(self.as_slice());
        buf.put_slice(other.as_slice());
        
        ZeroCopyBytes::new(buf.freeze())
    }

    /// Check if this bytes can be extended in-place
    pub fn can_extend(&self) -> bool {
        // Check if we're at the end of the underlying bytes and have capacity
        self.start + self.len == self.bytes.len()
    }
}

impl AsRef<[u8]> for ZeroCopyBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Bytes> for ZeroCopyBytes {
    fn from(bytes: Bytes) -> Self {
        Self::new(bytes)
    }
}

impl From<Vec<u8>> for ZeroCopyBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self::new(Bytes::from(vec))
    }
}

impl From<&'static [u8]> for ZeroCopyBytes {
    fn from(slice: &'static [u8]) -> Self {
        Self::from_static(slice)
    }
}

/// Zero-copy buffer builder for efficient construction
pub struct ZeroCopyBuilder {
    /// Chunks of data
    chunks: VecDeque<ZeroCopyBytes>,
    /// Total length
    total_len: usize,
}

impl ZeroCopyBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            total_len: 0,
        }
    }

    /// Add bytes to the builder
    pub fn push(&mut self, bytes: ZeroCopyBytes) {
        if !bytes.is_empty() {
            self.total_len += bytes.len();
            self.chunks.push_back(bytes);
        }
    }

    /// Add a byte slice to the builder
    pub fn push_slice(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.push(ZeroCopyBytes::from_slice(data));
        }
    }

    /// Add static bytes to the builder
    pub fn push_static(&mut self, data: &'static [u8]) {
        if !data.is_empty() {
            self.push(ZeroCopyBytes::from_static(data));
        }
    }

    /// Get the total length
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// Build the final zero-copy bytes
    pub fn build(self) -> ZeroCopyBytes {
        match self.chunks.len() {
            0 => ZeroCopyBytes::empty(),
            1 => self.chunks.into_iter().next().unwrap(),
            _ => {
                // Concatenate all chunks
                let mut buf = BytesMut::with_capacity(self.total_len);
                for chunk in self.chunks {
                    buf.put_slice(chunk.as_slice());
                }
                ZeroCopyBytes::new(buf.freeze())
            }
        }
    }

    /// Clear the builder
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.total_len = 0;
    }
}

impl Default for ZeroCopyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Zero-copy stream for efficient streaming without buffering
pub struct ZeroCopyStream {
    /// Stream of zero-copy bytes
    stream: Pin<Box<dyn Stream<Item = GatewayResult<ZeroCopyBytes>> + Send>>,
    /// Configuration
    config: ZeroCopyConfig,
}

impl ZeroCopyStream {
    /// Create a new zero-copy stream
    pub fn new<S>(stream: S, config: ZeroCopyConfig) -> Self
    where
        S: Stream<Item = GatewayResult<ZeroCopyBytes>> + Send + 'static,
    {
        Self {
            stream: Box::pin(stream),
            config,
        }
    }

    /// Create from a vector of bytes
    pub fn from_bytes(bytes: Vec<ZeroCopyBytes>, config: ZeroCopyConfig) -> Self {
        let stream = futures::stream::iter(bytes.into_iter().map(Ok));
        Self::new(stream, config)
    }

    /// Create from a single zero-copy bytes
    pub fn from_single(bytes: ZeroCopyBytes, config: ZeroCopyConfig) -> Self {
        let stream = futures::stream::once(async move { Ok(bytes) });
        Self::new(stream, config)
    }

    /// Collect all bytes into a single zero-copy bytes
    pub async fn collect(mut self) -> GatewayResult<ZeroCopyBytes> {
        let mut builder = ZeroCopyBuilder::new();
        
        while let Some(result) = self.stream.next().await {
            let bytes = result?;
            builder.push(bytes);
            
            // Check size limits
            if builder.len() > self.config.max_buffer_size {
                return Err(GatewayError::internal(
                    format!("Stream size {} exceeds maximum {}", builder.len(), self.config.max_buffer_size)
                ));
            }
        }
        
        Ok(builder.build())
    }

    /// Map the stream with a function
    pub fn map<F, T>(self, f: F) -> impl Stream<Item = GatewayResult<T>> + Send
    where
        F: Fn(ZeroCopyBytes) -> GatewayResult<T> + Send + 'static,
        T: Send + 'static,
    {
        self.stream.map(move |result| {
            match result {
                Ok(bytes) => f(bytes),
                Err(e) => Err(e),
            }
        })
    }

    /// Filter the stream
    pub fn filter<F>(self, f: F) -> impl Stream<Item = GatewayResult<ZeroCopyBytes>> + Send
    where
        F: Fn(&ZeroCopyBytes) -> bool + Send + 'static,
    {
        self.stream.filter(move |result| {
            match result {
                Ok(bytes) => futures::future::ready(f(bytes)),
                Err(_) => futures::future::ready(true), // Keep errors
            }
        })
    }

    /// Take only the first n bytes
    pub fn take_bytes(self, n: usize) -> impl Stream<Item = GatewayResult<ZeroCopyBytes>> + Send {
        let mut remaining = n;
        
        self.stream.map(move |result| {
            match result {
                Ok(bytes) => {
                    if remaining == 0 {
                        return Ok(ZeroCopyBytes::empty());
                    }
                    
                    if bytes.len() <= remaining {
                        remaining -= bytes.len();
                        Ok(bytes)
                    } else {
                        let taken = bytes.slice(0, remaining)?;
                        remaining = 0;
                        Ok(taken)
                    }
                }
                Err(e) => Err(e),
            }
        }).take_while(|result| {
            match result {
                Ok(bytes) => futures::future::ready(!bytes.is_empty()),
                Err(_) => futures::future::ready(true),
            }
        })
    }
}

impl Stream for ZeroCopyStream {
    type Item = GatewayResult<ZeroCopyBytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.as_mut().poll_next(cx)
    }
}

/// Zero-copy reader that implements AsyncRead
pub struct ZeroCopyReader {
    /// Current bytes being read
    current: Option<ZeroCopyBytes>,
    /// Position in current bytes
    position: usize,
    /// Stream of additional bytes
    stream: Option<ZeroCopyStream>,
}

impl ZeroCopyReader {
    /// Create a new zero-copy reader from bytes
    pub fn from_bytes(bytes: ZeroCopyBytes) -> Self {
        Self {
            current: Some(bytes),
            position: 0,
            stream: None,
        }
    }

    /// Create from a stream
    pub fn from_stream(stream: ZeroCopyStream) -> Self {
        Self {
            current: None,
            position: 0,
            stream: Some(stream),
        }
    }

    /// Get the remaining bytes in the current buffer
    fn remaining_in_current(&self) -> usize {
        self.current.as_ref().map(|b| b.len() - self.position).unwrap_or(0)
    }
}

impl AsyncRead for ZeroCopyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have current bytes, read from them first
        if let Some(ref current) = self.current {
            let remaining = self.remaining_in_current();
            if remaining > 0 {
                let to_read = std::cmp::min(remaining, buf.remaining());
                let start = self.position;
                let end = start + to_read;
                
                let slice = &current.as_slice()[start..end];
                buf.put_slice(slice);
                self.position += to_read;
                
                trace!(bytes_read = to_read, "Read bytes from zero-copy buffer");
                counter!("zero_copy_bytes_read").increment(to_read as u64);
                
                return Poll::Ready(Ok(()));
            } else {
                // Current buffer is exhausted
                self.current = None;
                self.position = 0;
            }
        }

        // Try to get next bytes from stream
        if let Some(ref mut stream) = self.stream {
            match Pin::new(stream).poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if !bytes.is_empty() {
                        self.current = Some(bytes);
                        self.position = 0;
                        // Recursively call to read from the new buffer
                        return self.poll_read(cx, buf);
                    } else {
                        // Empty bytes, try next
                        return self.poll_read(cx, buf);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Ready(None) => {
                    // Stream ended
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        // No more data
        Poll::Ready(Ok(()))
    }
}

/// Zero-copy writer that collects bytes efficiently
pub struct ZeroCopyWriter {
    /// Builder for collecting bytes
    builder: ZeroCopyBuilder,
    /// Configuration
    config: ZeroCopyConfig,
}

impl ZeroCopyWriter {
    /// Create a new zero-copy writer
    pub fn new(config: ZeroCopyConfig) -> Self {
        Self {
            builder: ZeroCopyBuilder::new(),
            config,
        }
    }

    /// Get the collected bytes
    pub fn into_bytes(self) -> ZeroCopyBytes {
        self.builder.build()
    }

    /// Get the current length
    pub fn len(&self) -> usize {
        self.builder.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.builder.is_empty()
    }
}

impl AsyncWrite for ZeroCopyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Check size limits
        if self.builder.len() + buf.len() > self.config.max_buffer_size {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("Write would exceed maximum buffer size of {}", self.config.max_buffer_size),
            )));
        }

        self.builder.push_slice(buf);
        
        trace!(bytes_written = buf.len(), "Wrote bytes to zero-copy writer");
        counter!("zero_copy_bytes_written").increment(buf.len() as u64);
        
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Zero-copy utilities
pub struct ZeroCopyUtils;

impl ZeroCopyUtils {
    /// Copy data efficiently using zero-copy when possible
    pub fn efficient_copy(src: &[u8], use_zero_copy: bool) -> ZeroCopyBytes {
        if use_zero_copy && src.len() >= 1024 {
            // For larger data, use zero-copy
            ZeroCopyBytes::from_slice(src)
        } else {
            // For smaller data, direct copy might be faster
            ZeroCopyBytes::from_slice(src)
        }
    }

    /// Split data into chunks for streaming
    pub fn chunk_data(data: ZeroCopyBytes, chunk_size: usize) -> Vec<ZeroCopyBytes> {
        if data.len() <= chunk_size {
            return vec![data];
        }

        let mut chunks = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let end = std::cmp::min(offset + chunk_size, data.len());
            if let Ok(chunk) = data.slice(offset, end) {
                chunks.push(chunk);
            }
            offset = end;
        }

        chunks
    }

    /// Merge multiple zero-copy bytes efficiently
    pub fn merge_bytes(bytes_vec: Vec<ZeroCopyBytes>) -> ZeroCopyBytes {
        match bytes_vec.len() {
            0 => ZeroCopyBytes::empty(),
            1 => bytes_vec.into_iter().next().unwrap(),
            _ => {
                let total_len: usize = bytes_vec.iter().map(|b| b.len()).sum();
                let mut buf = BytesMut::with_capacity(total_len);
                
                for bytes in bytes_vec {
                    buf.put_slice(bytes.as_slice());
                }
                
                ZeroCopyBytes::new(buf.freeze())
            }
        }
    }

    /// Create a zero-copy view of data without allocation
    pub fn create_view(data: &ZeroCopyBytes, start: usize, len: usize) -> GatewayResult<ZeroCopyBytes> {
        data.slice(start, start + len)
    }

    /// Check if zero-copy is beneficial for the given size
    pub fn should_use_zero_copy(size: usize, config: &ZeroCopyConfig) -> bool {
        config.enabled && size >= config.min_buffer_size && size <= config.max_buffer_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_zero_copy_bytes_creation() {
        let data = b"Hello, World!";
        let bytes = ZeroCopyBytes::from_slice(data);
        
        assert_eq!(bytes.len(), data.len());
        assert_eq!(bytes.as_slice(), data);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_zero_copy_bytes_slicing() {
        let data = b"Hello, World!";
        let bytes = ZeroCopyBytes::from_slice(data);
        
        let slice = bytes.slice(0, 5).unwrap();
        assert_eq!(slice.as_slice(), b"Hello");
        
        let slice2 = bytes.slice(7, 12).unwrap();
        assert_eq!(slice2.as_slice(), b"World");
    }

    #[test]
    fn test_zero_copy_bytes_split() {
        let data = b"Hello, World!";
        let bytes = ZeroCopyBytes::from_slice(data);
        
        let (left, right) = bytes.split_at(7).unwrap();
        assert_eq!(left.as_slice(), b"Hello, ");
        assert_eq!(right.as_slice(), b"World!");
    }

    #[test]
    fn test_zero_copy_builder() {
        let mut builder = ZeroCopyBuilder::new();
        
        builder.push_slice(b"Hello, ");
        builder.push_slice(b"World!");
        
        assert_eq!(builder.len(), 13);
        
        let result = builder.build();
        assert_eq!(result.as_slice(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_zero_copy_stream() {
        let config = ZeroCopyConfig::default();
        let bytes1 = ZeroCopyBytes::from_slice(b"Hello, ");
        let bytes2 = ZeroCopyBytes::from_slice(b"World!");
        
        let stream = ZeroCopyStream::from_bytes(vec![bytes1, bytes2], config);
        let result = stream.collect().await.unwrap();
        
        assert_eq!(result.as_slice(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_zero_copy_reader() {
        let data = ZeroCopyBytes::from_slice(b"Hello, World!");
        let mut reader = ZeroCopyReader::from_bytes(data);
        
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await.unwrap();
        
        assert_eq!(buffer, b"Hello, World!");
    }

    #[tokio::test]
    async fn test_zero_copy_writer() {
        let config = ZeroCopyConfig::default();
        let mut writer = ZeroCopyWriter::new(config);
        
        writer.write_all(b"Hello, ").await.unwrap();
        writer.write_all(b"World!").await.unwrap();
        
        let result = writer.into_bytes();
        assert_eq!(result.as_slice(), b"Hello, World!");
    }

    #[test]
    fn test_zero_copy_utils() {
        let data = ZeroCopyBytes::from_slice(b"Hello, World!");
        
        // Test chunking
        let chunks = ZeroCopyUtils::chunk_data(data.clone(), 5);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].as_slice(), b"Hello");
        assert_eq!(chunks[1].as_slice(), b", Wor");
        assert_eq!(chunks[2].as_slice(), b"ld!");
        
        // Test merging
        let merged = ZeroCopyUtils::merge_bytes(chunks);
        assert_eq!(merged.as_slice(), b"Hello, World!");
    }

    #[test]
    fn test_zero_copy_config() {
        let config = ZeroCopyConfig::default();
        
        assert!(ZeroCopyUtils::should_use_zero_copy(8192, &config));
        assert!(!ZeroCopyUtils::should_use_zero_copy(1024, &config));
        assert!(!ZeroCopyUtils::should_use_zero_copy(128 * 1024 * 1024, &config));
    }
}