use std::{
    fs::File,
    io::{BufReader, ErrorKind},
    sync::Arc,
};

use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{read_one, Item};
use tokio_uring::net::TcpListener;
use tokio_uring_rustls::TlsAcceptor;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8000".parse().unwrap()).unwrap();

    // Load certificates and keys
    let certificates = load_certs("./certs/cert.pem").unwrap();
    let key = load_private_key("./certs/key.pem").unwrap();

    // Use self signed certs for testing
    let cfg = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("bad certificate/key");

    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    tokio_uring::start(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();

            println!("Received new connection");

            let mut stream = acceptor.accept(socket).await.unwrap();

            println!("Finished handshake successfully");

            // Read from input tls stream
            let buf = vec![0u8; 256];
            let (res, buf) = stream.read(buf).await;
            match res {
                Ok(n) => println!("read: {:?}", std::str::from_utf8(&buf[..n])),
                Err(_) => (),
            }

            // Write to tls stream
            let data = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".as_bytes();
            let (_, _) = stream.write(data).await;
        }
    });
}

fn load_certs(path: &str) -> std::io::Result<Vec<Certificate>> {
    let mut reader = match File::open(path) {
        Ok(file) => BufReader::new(file),
        Err(e) => {
            return Err(e);
        }
    };

    return match rustls_pemfile::certs(&mut reader) {
        Ok(certs) => Ok(certs.into_iter().map(|bytes| Certificate(bytes)).collect()),
        Err(_) => Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "failed to load tls certificate",
        )),
    };
}

fn load_private_key(path: &str) -> std::io::Result<PrivateKey> {
    let mut reader = match File::open(path) {
        Ok(file) => BufReader::new(file),
        Err(e) => return Err(e),
    };

    return match read_one(&mut reader) {
        Ok(opt) => match opt {
            Some(item) => match item {
                Item::RSAKey(key) => Ok(rustls::PrivateKey(key)),
                Item::PKCS8Key(key) => Ok(rustls::PrivateKey(key)),
                Item::ECKey(key) => Ok(rustls::PrivateKey(key)),
                _ => Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Found cert in ssl key file",
                )),
            },
            None => Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Failed to find any private key in file",
            )),
        },
        Err(e) => Err(e),
    };
}
