use crate::buffer::{SyncReadAdaptor, SyncWriteAdaptor};

use rustls::{ConnectionCommon, SideData};
use std::{
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
};
use tokio_uring::{net::TcpStream, BufResult};

pub struct TlsStream<C> {
    pub(crate) io: TcpStream,
    pub(crate) session: C,
    pub(crate) rbuffer: SyncReadAdaptor,
    pub(crate) wbuffer: SyncWriteAdaptor,
}

impl<C, SD: SideData> TlsStream<C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub fn new(io: TcpStream, session: C) -> Self {
        TlsStream {
            io,
            session,
            rbuffer: SyncReadAdaptor::default(),
            wbuffer: SyncWriteAdaptor::default(),
        }
    }

    async fn read_io(&mut self) -> io::Result<usize> {
        let n = loop {
            match self.session.read_tls(&mut self.rbuffer) {
                Ok(n) => {
                    break n;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.rbuffer.do_io(&mut self.io).await?;
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        let state = match self.session.process_new_packets() {
            Ok(state) => state,
            Err(err) => {
                // When to write_io? If we do this in read call, the UnsafeWrite may crash
                // when we impl split in an UnsafeCell way.
                // Here we choose not to do write when read.
                // User should manually shutdown it on error.
                // if !splitted {
                //     let _ = self.write_io().await;
                // }
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        if state.peer_has_closed() && self.session.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls handshake alert",
            ));
        }

        Ok(n)
    }

    async fn write_io(&mut self) -> io::Result<usize> {
        let n = loop {
            match self.session.write_tls(&mut self.wbuffer) {
                Ok(n) => {
                    break n;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.wbuffer.do_io(&mut self.io).await?;
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        self.wbuffer.do_io(&mut self.io).await?;

        Ok(n)
    }

    pub(crate) async fn handshake(&mut self) -> io::Result<(usize, usize)> {
        let mut wrlen = 0;
        let mut rdlen = 0;
        let mut eof = false;

        loop {
            while self.session.wants_write() && self.session.is_handshaking() {
                wrlen += self.write_io().await?;
            }

            while !eof && self.session.wants_read() && self.session.is_handshaking() {
                let n = self.read_io().await?;
                rdlen += n;
                if n == 0 {
                    eof = true;
                }
            }

            match (eof, self.session.is_handshaking()) {
                (true, true) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    return Err(err);
                }
                (false, true) => (),
                (_, false) => {
                    break;
                }
            };
        }

        // flush buffer
        while self.session.wants_write() {
            wrlen += self.write_io().await?;
        }

        Ok((rdlen, wrlen))
    }

    pub async fn read<B: tokio_uring::buf::IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        // Safety: bytes_total property promises the capacity of the buffer, such that we won't overrun.
        let slice =
            unsafe { std::slice::from_raw_parts_mut(buf.stable_mut_ptr(), buf.bytes_total()) };

        loop {
            // read from rustls to buffer
            match self.session.reader().read(slice) {
                Ok(n) => {
                    // Safety: we already know from the reader that we have read n bytes, so the n bytes must
                    // be stored in the buffer.
                    unsafe { buf.set_init(n) };

                    return (Ok(n), buf);
                }
                // we need more data, read something.
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => {
                    return (Err(e), buf);
                }
            }

            // now we need data, read something into rustls
            match self.read_io().await {
                Ok(0) => {
                    return (
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "tls raw stream eof",
                        )),
                        buf,
                    );
                }
                Ok(_) => (),
                Err(e) => {
                    return (Err(e), buf);
                }
            };
        }
    }

    pub async fn write<B: tokio_uring::buf::IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let slice = unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) };

        let size = match self.session.writer().write(slice) {
            Ok(l) => l,
            Err(e) => return (Err(e), buf),
        };

        if let Err(e) = self.session.writer().flush() {
            return (Err(e), buf);
        }

        while self.session.wants_write() {
            match self.write_io().await {
                Ok(0) => {
                    break;
                }
                Ok(_) => (),
                Err(e) => return (Err(e), buf),
            }
        }

        return (Ok(size), buf);
    }

    pub async fn write_all<B: tokio_uring::buf::IoBuf>(&mut self, buf: B) -> BufResult<(), B> {
        let slice = unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) };

        if let Err(e) = self.session.writer().write_all(slice) {
            return (Err(e), buf);
        }

        if let Err(e) = self.session.writer().flush() {
            return (Err(e), buf);
        }

        while self.session.wants_write() {
            match self.write_io().await {
                Ok(0) => {
                    break;
                }
                Ok(_) => (),
                Err(e) => return (Err(e), buf),
            }
        }

        return (Ok(()), buf);
    }
}
