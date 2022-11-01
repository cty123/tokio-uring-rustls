use std::{net::ToSocketAddrs, sync::Arc, time::SystemTime};

use rustls::{
    client::ServerCertVerified, client::ServerCertVerifier, Certificate, ClientConfig, ServerName,
};
use tokio_uring::net::TcpStream;
use tokio_uring_rustls::{TlsConnector, split};
pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn main() {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification {}));

    let connector = TlsConnector::from(std::sync::Arc::new(config));

    tokio_uring::start(async move {
        let socket = TcpStream::connect(
            ("www.google.com", 443)
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
        )
        .await
        .unwrap();

        let stream = connector
            .connect("www.google.com".try_into().unwrap(), socket)
            .await
            .unwrap();

        let (mut reader, mut writer) = split(stream);

        // Spawn read task
        let a = tokio_uring::spawn(async move {
            println!("Reader entering");
            let buf = vec![0u8; 1024 * 4];
            let (res, buf) = reader.read(buf).await;
            let n = res.unwrap();
            println!("Read: {:?}", std::str::from_utf8(&buf[..n]))
        });

        // Spawn write task
        let b = tokio_uring::spawn(async move {
            println!("Writer entering");
            let data = "GET / HTTP/1.1\r\n\r\n".as_bytes();
            let (_, _) = writer.write(data).await;
            println!("Finished writing");
        });

        tokio::join!(a, b);
    });
}
