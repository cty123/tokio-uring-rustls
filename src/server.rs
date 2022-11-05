use crate::stream::TlsStream;

use rustls::{ServerConfig, ServerConnection};
use std::{
    io::{self, Error, ErrorKind},
    sync::Arc,
};
use tokio_uring::net::TcpStream;

#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    #[inline]
    fn from(inner: Arc<ServerConfig>) -> TlsAcceptor {
        TlsAcceptor { inner }
    }
}

impl TlsAcceptor {
    pub async fn accept(&self, socket: TcpStream) -> io::Result<TlsStream<ServerConnection>> {
        let session = match ServerConnection::new(self.inner.clone()) {
            Ok(s) => s,
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        };
        let mut stream = TlsStream::new(socket, session);
        stream.handshake().await?;
        Ok(stream)
    }
}
