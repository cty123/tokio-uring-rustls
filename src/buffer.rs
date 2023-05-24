use core::panic;
use std::io;
use tokio_uring::{
    buf::{IoBuf, IoBufMut},
    net::TcpStream,
};

const BUFFER_SIZE: usize = 8 * 1024;

/// The following snippet of codes is directly copied from:
/// https://github.com/monoio-rs/monoio-tls/blob/master/monoio-rustls/src/safe_io.rs#L10
///
/// We will seek out other implementation of Ringbuffer in the future.
///
/// Copyright (c) 2022 ihciah and other Monoio Contributors
///                              Apache License
///                        Version 2.0, January 2004
///                     http://www.apache.org/licenses/
struct RingBuffer {
    read: usize,
    write: usize,
    capacity: usize,
    buf: Box<[u8]>,
}

impl RingBuffer {
    fn with_capacity(size: usize) -> Self {
        Self {
            read: 0,
            write: 0,
            buf: vec![0; size].into_boxed_slice(),
            capacity: size,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.write - self.read
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    fn available(&self) -> usize {
        self.capacity - self.write
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.available() == 0
    }

    fn advance(&mut self, n: usize) {
        assert!(self.write - self.read >= n);
        self.read += n;
        if self.read == self.write {
            self.read = 0;
            self.write = 0;
        }
    }
}

unsafe impl tokio_uring::buf::IoBuf for RingBuffer {
    fn bytes_init(&self) -> usize {
        self.write - self.read
    }

    fn stable_ptr(&self) -> *const u8 {
        unsafe { self.buf.as_ptr().add(self.read) }
    }

    fn bytes_total(&self) -> usize {
        self.capacity - self.write
    }
}

unsafe impl tokio_uring::buf::IoBufMut for RingBuffer {
    unsafe fn set_init(&mut self, pos: usize) {
        self.write += pos;
    }

    fn stable_mut_ptr(&mut self) -> *mut u8 {
        unsafe { self.buf.as_mut_ptr().add(self.write) }
    }
}

#[derive(Debug)]
enum ReadStatus {
    Eof,
    Err(io::Error),
    Ok,
}

pub(crate) struct SyncReadAdaptor {
    buffer: Option<RingBuffer>,
    status: ReadStatus,
}

impl Default for SyncReadAdaptor {
    fn default() -> Self {
        Self {
            buffer: Some(RingBuffer::with_capacity(BUFFER_SIZE)),
            status: ReadStatus::Ok,
        }
    }
}

impl SyncReadAdaptor {
    pub(crate) async fn do_io(&mut self, io: &mut TcpStream) -> io::Result<usize> {
        // Take the reference of the buffer. We already expect the buffer to be present instead of None
        let buffer = self.buffer.as_ref().expect("bug: buffer ref expected");

        // If there are some data inside the buffer, just return.
        if !buffer.is_empty() {
            return Ok(buffer.len());
        }

        // Unwrap buffer such that we can read from it. We always expect the buffer to be present.
        // So if the buffer is None, we definitely have a bug somewhere when we forgot to return the buffer.
        let buffer = self.buffer.take().expect("buffer ownership expected");

        // Call undelying read operation to fetch more data from IO
        let (result, buf) = io.read(buffer).await;

        // The previous take() will move the buffer out of the owner, here we need to return the buffer
        // as read operation has completed, such that we can reuse this buffer the next time we read.
        // We need to return the buffer regardless of the result of the read operation.
        self.buffer = Some(buf);

        // Properly set the status of the read operation and return result
        return match result {
            Ok(0) => {
                self.status = ReadStatus::Eof;
                result
            }
            Ok(_) => {
                self.status = ReadStatus::Ok;
                result
            }
            Err(e) => {
                let rerr = e.kind().into();
                self.status = ReadStatus::Err(e);
                Err(rerr)
            }
        };
    }
}

impl io::Read for SyncReadAdaptor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Can't read anything if the reader buffer is empty.
        if buf.len() == 0 {
            return Ok(0);
        }

        // Unwrap buffer such that we can read from it. We always expect the buffer to be present.
        // So if the buffer is None, we definitely have a bug somewhere when we forgot to return the buffer.
        let buffer = self.buffer.as_mut().expect("buffer mut expected");

        // If buffer is empty, we need to check for 2 cases:
        //   1. Buffer empty due to previous read operation failure: broken pipe, EOF etc.
        //   2. No read operation so far. Ex. read operation never started
        if buffer.is_empty() {
            // For case #1, we should properly handle the failure by returning appropriate error status code.
            if !matches!(self.status, ReadStatus::Ok) {
                match std::mem::replace(&mut self.status, ReadStatus::Ok) {
                    ReadStatus::Eof => return Ok(0),
                    ReadStatus::Err(e) => return Err(e),
                    ReadStatus::Ok => panic!("bug: unexpected branch"),
                }
            }

            // For case #2, we should return would block error to indicate that read operation is not ready yet,
            // and it's up to the caller to start read operation and keep polling. Returning would block error
            // is similar to returning Poll::Pending for async operations.
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // Since the buffer is not empty, we should have some data to return to the caller
        let copy_size = buffer.len().min(buf.len());

        // Safety: in the above line, we have checked length of both buffers, and we taken the min of them
        unsafe { std::ptr::copy_nonoverlapping(buffer.stable_ptr(), buf.as_mut_ptr(), copy_size) };

        // Advance buffer for copy_size bytes, as we have already copied them to the reader buffer
        buffer.advance(copy_size);

        Ok(copy_size)
    }
}

#[derive(Debug)]
enum WriteStatus {
    Err(io::Error),
    Ok,
}

pub(crate) struct SyncWriteAdaptor {
    buffer: Option<RingBuffer>,
    status: WriteStatus,
}

impl Default for SyncWriteAdaptor {
    fn default() -> Self {
        Self {
            buffer: Some(RingBuffer::with_capacity(BUFFER_SIZE)),
            status: WriteStatus::Ok,
        }
    }
}

impl SyncWriteAdaptor {
    pub(crate) async fn do_io(&mut self, io: &mut TcpStream) -> io::Result<usize> {
        // If buffer is empty, we don't have any additional data to write
        if self.buffer.as_ref().unwrap().is_empty() {
            return Ok(0);
        }

        // Unwrap buffer such that we can read from it. We always expect the buffer to be present.
        // So if the buffer is None, we definitely have a bug somewhere when we forgot to return the buffer.
        let buffer = self.buffer.take().expect("bug: buffer ownership expected");

        // Call write operation on io to flush the data in the buffer
        let (result, buffer) = io.write(buffer).await;

        // Regardless of the result of the write operation, we always need to return the buffer to the owner
        // such that the next write operation is able to use it.
        self.buffer = Some(buffer);

        // Check result and march inner buffer if successfully written
        match result {
            Ok(n) => {
                // Safety: buffer unwrap should always be successful because we just returned the buffer
                unsafe { self.buffer.as_mut().unwrap_unchecked().advance(n) };
                Ok(n)
            }
            Err(e) => {
                let rerr = e.kind().into();
                self.status = WriteStatus::Err(e);
                Err(rerr)
            }
        }
    }
}

impl io::Write for SyncWriteAdaptor {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Nothing to write if the buffer is emtpy
        if buf.is_empty() {
            return Ok(0);
        }

        // Unwrap buffer such that we can read from it. We always expect the buffer to be present.
        // So if the buffer is None, we definitely have a bug somewhere when we forgot to return the buffer.
        let buffer = self.buffer.as_mut().expect("bug: buffer mut expected");

        // We need to check if previous write operation is successful or not. If previous write operation errored
        // out, we should catch and raise exception.
        if !matches!(self.status, WriteStatus::Ok) {
            match std::mem::replace(&mut self.status, WriteStatus::Ok) {
                WriteStatus::Err(e) => return Err(e),
                WriteStatus::Ok => panic!("bug: unexpected branch"),
            }
        }

        // If we have absolutely 0 available spots in the buffer, instead of growing the buffer capacity,
        // we would want to flush it first.
        if buffer.is_full() {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        // If the payload size is larger than the buffer can actually take, we do our best to fill the buffer.
        let copy_size = buffer.available().min(buf.len());
        unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), buffer.stable_mut_ptr(), copy_size) };
        unsafe { buffer.set_init(copy_size) };

        Ok(copy_size)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Unwrap buffer such that we can read from it. We always expect the buffer to be present.
        // So if the buffer is None, we definitely have a bug somewhere when we forgot to return the buffer.
        let buffer = self.buffer.as_mut().expect("buffer mut expected");

        // We need to check if previous write operation is successful or not. If previous write operation errored
        // out, we should catch and raise exception.
        if !matches!(self.status, WriteStatus::Ok) {
            match std::mem::replace(&mut self.status, WriteStatus::Ok) {
                WriteStatus::Err(e) => return Err(e),
                WriteStatus::Ok => panic!("bug: unexpected branch"),
            }
        }

        // Flush operation is never successful unless the entire buffer is flushed. So if we still see some data in the
        // buffer, it means the socket hasn't written all the data. Returning WouldBlock here is similar to returning
        // Poll::Pending in async operations.
        if !buffer.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }

        Ok(())
    }
}
