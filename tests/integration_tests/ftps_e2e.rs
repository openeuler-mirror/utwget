//! End-to-end test: FTPS explicit mode (AUTH TLS) over a domain name.
//!
//! Spawns an in-process rustls-backed FTPS server (deterministic, no flaky
//! external mock servers) and downloads a file through `FtpsClient`.
//!
//! Regression coverage:
//! - P0 PASV fix: the client connects with the host name `localhost` while
//!   PASV advertises `127.0.0.1`. The bounce-attack check must compare the
//!   PASV IP against the control socket's peer IP (they match), NOT the
//!   host-name string (it never matches) — the old code rejected every
//!   FTPS-over-domain-name connection.
//! - TLS 1.3 handshake deadlock fix: the client flight (CKE/CV/Finished)
//!   is queued when the server's Finished is processed, the same moment
//!   `is_handshaking()` flips to false — it must be flushed before the
//!   handshake loop exits, otherwise both peers wait forever.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

use ut_ftp::ftps::FtpsClient;
use ut_ftp::FtpsConfig;

const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUBk5UAvsqUTzldpIFzJmHAxo8mH8wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkxMTAyMTIzNFoXDTI2MTAx
MTAyMTIzNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAu8uTiJfChSITEMTxpZkfK/WKC1qM+MOB+UfjXtykpqUv
34ve5dXYr76GNqFXE48QWnvolBXM2OotqA9VAN9T92duiwDTrXLwNYVdbdTzhjBH
q8i2BTINW/RfEf5CgY4K5WY/yQ1V/bdJSUKvkCPRp/JQmRuaCOi+bu5SZtD4c4ij
8mXRvlK8r+yPlEyFIxUBCDJE757TW4bza8IiioFQo98VONoiVV6LP8A+zHmL7FkY
4/7XN87QxgtpF3iexMGophq3Ufjc10oMon/SpPcFpHPAsn+m6OEFJ5mQ1N6g60Yx
E7dySH7mrEI8Iz/XBcaBbiTbYOb8+MB6QGnAduGwkwIDAQABo28wbTAdBgNVHQ4E
FgQUr5ZDqK0lq8pie86PrDr84a8AEwEwHwYDVR0jBBgwFoAUr5ZDqK0lq8pie86P
rDr84a8AEwEwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAEPq+6hBj6wbZ8qijKHviG3WP80NxVo5
bDj0NRozqGsggNgBSXqBcEht/t4nhfjrjYoD3FzdwJnt6ibdpVttPwHBWQYZB6Si
EdgYdBvuXa9TGsoF0whxGewZPDGGKCITRQ6lPm+3rfmtn41J3JL/Yz8g4+fEoUe6
1rKZeCMmL21iiX3MxpmvRZptRJlErlXhLGDwmF3C+EvpVsOHxoYLHcnzxYD3y4ph
iYcrcFKK2P2U7Owdz0Ify5MSlsxxGi22lF+9Bm2iqkClzf6qVmjCHZO4glRSsqw6
1OKaW1+TxLdwSKtKXHu7vlsFqofT93a/XPrHV4/r4pp/JbKA7B/GZ4M=
-----END CERTIFICATE-----";

const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC7y5OIl8KFIhMQ
xPGlmR8r9YoLWoz4w4H5R+Ne3KSmpS/fi97l1divvoY2oVcTjxBae+iUFczY6i2o
D1UA31P3Z26LANOtcvA1hV1t1POGMEeryLYFMg1b9F8R/kKBjgrlZj/JDVX9t0lJ
Qq+QI9Gn8lCZG5oI6L5u7lJm0PhziKPyZdG+Uryv7I+UTIUjFQEIMkTvntNbhvNr
wiKKgVCj3xU42iJVXos/wD7MeYvsWRjj/tc3ztDGC2kXeJ7EwaimGrdR+NzXSgyi
f9Kk9wWkc8Cyf6bo4QUnmZDU3qDrRjETt3JIfuasQjwjP9cFxoFuJNtg5vz4wHpA
acB24bCTAgMBAAECggEBAKvIa9td3x0Db2c+kEFH0SDYCX+bRCrmREVwQgdrU93w
attVSf75363bXVApw8praq0qfTTAwFKH3F3IMJyMrXU5kv/qMLeP1TVQGoe2bVEJ
ZvY3snEMOPYtkq2V5OY3tbXkE2LpJQjiGVK/gnMaoNS9LobvnbaamGBG9u+AJlUf
TiKPhUKPYAjC7fAW9sIG6tpboMjsqZu1Wp3KPbz5E4EE20vP9Y3hWQqeyCHRpaUh
fJ3UxZqRq3+Lzgkn0eWoKbHBTDSbR6dmSQwhLhGe76W+Qxs9MGBv2BkSwvKHGjq7
JPKRhG87jNInVmY96wb4LNGeHuxPOshspllQrFyS0xkCgYEA5kNAJ+GATM8xJE/R
w/EYUmXS4+msLWJunEhIErx2QCk9OslNBzLRubh/W4Iu0ugBOggZUUnpVNoNRh5W
8iy2xfE1SQzodVF8xxayOC9axdmHIUCgJam8uhvA2fq+YJZrSLA7ndjTFQzpupG4
4SqinTIgWsGSDYkYW2f5u1JykwcCgYEA0MkosjpN/KooalP0mpz436J+jkpQOa9t
qNZX0fucwrU+qm40eFxI7xQ0MpUwhtigrh//YvD4STCW52t3Dvzw2jNW+DR9Ljd2
qNvOYTRB+Vaiz7fnmC4DPjf59EQnKEtwAJTAnaHeWnGqaqW2Jng0ghdSvHkYStxD
/dYSXYYKFxUCgYEAzk3mx1SVPTxNzTjuul3i6sBsSONt7mPIsqFYYeEVGbtZLrh5
GUABBCM3iGeFSFWx86qZ9GkCc5HCXtaEFArX31WT5lV4WNSftUiyeQCElcul9LcQ
RW5kt2JyUVsFA0kB6mhroatIxA2DxDMXsDYg6DKnJmlUUGhKuGraJ2lhWjUCgYEA
jasBDzZatofrFoLTJZo/kNdckkZAe3Par8aJHnVhYAjFdbWDquvLnVYTOQNcQxN4
q84QZ11ky5zJuEuGJMhi0VwmthI/on2F6XwEZJal8X7kyJdb8Tm/f5dR5nncLA5L
+Ej3Db7I9ovL+8NnfmDwGBmlTTfJ0Pn2tKVuHsGV1SUCgYEAux1JXKoid7F6DD6x
8LIThhfUd8NbNRmHwNUiToIfEEVzcvuLp/iiFJUruTSaK325111iBAB+ReuiPx+T
kTl36sx/DckqIn8xYE5dBZfFCR8Z2PwvhHWeXTjrPbaJP3k29W3WFxQXE5V8lKsi
uEX4V/S2UJouT/LH5CMC1w7PZ8g=
-----END PRIVATE KEY-----";

const FILE_CONTENT: &[u8] = b"FTPS-DOMAIN-OK-CONTENT";

/// Read one CRLF-terminated line (FTP command) from a plaintext stream.
fn read_plain_line(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf)
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

/// Build a rustls server config accepting TLS 1.2/1.3, no client auth.
///
/// The crypto provider must be pinned explicitly: the dependency closure
/// enables both `ring` and `aws-lc-rs`, which makes rustls' process-default
/// provider ambiguous (ClientConfig::builder* would panic).
fn server_tls_config() -> Arc<ServerConfig> {
    let certs: Vec<CertificateDer<'static>> =
        vec![CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).expect("parse cert pem")];
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).expect("parse key pem");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert/key")
        .into()
}

/// Drive the TLS handshake as the server side (blocking, with a step guard).
fn tls_accept(stream: &mut TcpStream, cfg: Arc<ServerConfig>) -> std::io::Result<ServerConnection> {
    let mut conn = ServerConnection::new(cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut steps = 0usize;
    while conn.is_handshaking() {
        steps += 1;
        if steps > 100 {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake stuck"));
        }
        if conn.wants_write() {
            conn.write_tls(stream)?;
            continue;
        }
        if conn.wants_read() {
            if conn.read_tls(stream)? == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            conn.process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
    }
    Ok(conn)
}

/// Line-oriented helper over a completed server-side TLS connection.
struct TlsLines<'a> {
    conn: ServerConnection,
    stream: &'a mut TcpStream,
    buf: Vec<u8>,
}

impl<'a> TlsLines<'a> {
    fn read_line(&mut self) -> std::io::Result<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Ok(String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .to_string());
            }
            if self.conn.wants_write() {
                self.conn.write_tls(self.stream)?;
            }
            // Process records already buffered from a previous read_tls
            // before blocking on the socket (same segment coalescing).
            self.conn
                .process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            // Drain plaintext; rustls signals "buffer drained, still alive"
            // as Err(WouldBlock), which must end the drain loop.
            {
                let mut reader = self.conn.reader();
                let mut tmp = [0u8; 4096];
                loop {
                    match reader.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::UnexpectedEof =>
                        {
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            // Loop back: the drain may have produced a complete line. Only
            // block on the socket when no line is available yet.
            if self.buf.iter().any(|b| *b == b'\n') {
                continue;
            }
            // Pull more ciphertext (blocks until data or EOF).
            if self.conn.read_tls(self.stream)? == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
        }
    }

    fn send(&mut self, text: &str) -> std::io::Result<()> {
        self.conn.writer().write_all(text.as_bytes())?;
        while self.conn.wants_write() {
            self.conn.write_tls(self.stream)?;
        }
        Ok(())
    }
}

#[test]
fn ftps_explicit_domain_name_download() {
    let _ = env_logger::try_init();
    let ctrl_listener = TcpListener::bind("127.0.0.1:0").expect("bind ctrl");
    let ctrl_port = ctrl_listener.local_addr().unwrap().port();

    let server = std::thread::spawn(move || {
        let (stream, _) = ctrl_listener.accept().expect("accept ctrl");
        stream.set_nonblocking(false).expect("set blocking");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .ok();
        let mut s = stream;

        // Plaintext banner, then AUTH TLS.
        s.write_all(b"220 mock ready\r\n").unwrap();
        let cmd = read_plain_line(&mut s).expect("read AUTH TLS");
        assert_eq!(cmd, "AUTH TLS", "client must send AUTH TLS first");
        s.write_all(b"234 proceed with TLS\r\n").unwrap();

        // TLS handshake.
        let conn = tls_accept(&mut s, server_tls_config()).expect("server TLS handshake");
        let mut tls = TlsLines {
            conn,
            stream: &mut s,
            buf: Vec::new(),
        };

        let mut data_listener: Option<TcpListener> = None;
        loop {
            let cmd = tls.read_line().expect("read command over TLS");
            match cmd.as_str() {
                "USER u" => tls.send("331 need password\r\n").unwrap(),
                "PASS p" => tls.send("230 logged in\r\n").unwrap(),
                "PBSZ 0" => tls.send("200 PBSZ=0\r\n").unwrap(),
                "PROT P" => tls.send("200 PROT P\r\n").unwrap(),
                "TYPE I" | "TYPE A" => tls.send("200 type set\r\n").unwrap(),
                "PASV" => {
                    let l = TcpListener::bind("127.0.0.1:0").unwrap();
                    let port = l.local_addr().unwrap().port();
                    tls.send(&format!(
                        "227 Entering Passive Mode (127,0,0,1,{},{})\r\n",
                        port / 256,
                        port % 256
                    ))
                    .unwrap();
                    data_listener = Some(l);
                }
                c if c.starts_with("RETR") => {
                    tls.send("150 opening data connection\r\n").unwrap();
                    let listener = data_listener.take().expect("PASV before RETR");
                    let (mut dstream, _) = listener.accept().unwrap();
                    dstream
                        .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                        .ok();
                    let mut dconn = tls_accept(&mut dstream, server_tls_config())
                        .expect("data TLS handshake");
                    dconn.writer().write_all(FILE_CONTENT).unwrap();
                    while dconn.wants_write() {
                        dconn.write_tls(&mut dstream).unwrap();
                    }
                    let _ = dconn.send_close_notify();
                    while dconn.wants_write() {
                        dconn.write_tls(&mut dstream).unwrap();
                    }
                    // Give the client a moment to drain the data connection
                    // before responding on the control channel.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    tls.send("226 transfer complete\r\n").unwrap();
                }
                c if c.starts_with("QUIT") => {
                    tls.send("221 bye\r\n").unwrap();
                    return;
                }
                other => panic!("unexpected command: {:?}", other),
            }
        }
    });

    let mut client = FtpsClient::with_config(FtpsConfig {
        verify_certificate: false,
        ..Default::default()
    });
    client
        .connect_explicit("localhost", ctrl_port)
        .expect("explicit FTPS connect (AUTH TLS)");
    client.login("u", "p").expect("login");
    client.type_binary().expect("TYPE I");

    let mut out = Vec::new();
    let n = client.retr("file.bin", &mut out, None).expect("RETR");
    assert_eq!(n, FILE_CONTENT.len() as u64);
    assert_eq!(out, FILE_CONTENT);
    let _ = client.quit();

    server.join().expect("server thread");
}
