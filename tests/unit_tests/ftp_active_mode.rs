//! Regression tests for FTP active mode (H-7).
//!
//! The PORT command used to advertise `0,0,0,0` (taken from a listener
//! bound to 0.0.0.0) instead of the control connection's local IP —
//! compliant servers reject that. These tests verify that the advertised
//! IP is the control connection's local address via a mock FTP server
//! that echoes the PORT command back for inspection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use ut_ftp::data_conn::bind_active_listener;

// ============================================================================
// bind_active_listener unit tests
// ============================================================================

#[test]
fn advertised_ip_is_control_local_ip() {
    // Control connection on 127.0.0.1 → PORT must advertise 127.0.0.1,
    // NOT 0.0.0.0.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let ctrl_port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
    });
    let ctrl = TcpStream::connect(("127.0.0.1", ctrl_port)).expect("connect");
    let ctrl_local_ip = ctrl.local_addr().unwrap().ip();

    let (_data_listener, advertise_ip, _port) = bind_active_listener(Some(ctrl_local_ip))
        .expect("bind active listener");
    assert_eq!(
        advertise_ip, ctrl_local_ip,
        "PORT must advertise the control connection's local IP"
    );
    assert_ne!(
        advertise_ip,
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        "PORT must never advertise 0.0.0.0 (H-7)"
    );
    handle.join().unwrap();
}

#[test]
fn ipv6_control_connection_gets_ipv6_listener() {
    // Control over IPv6 → the listener should be an IPv6 listener so the
    // server can actually connect back (the old code always bound IPv4,
    // making EPRT unreachable on dual-stack hosts).
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(l) => l,
        Err(_) => return, // no IPv6 support in this environment
    };
    let ctrl_addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
    });
    let ctrl = TcpStream::connect(&ctrl_addr).expect("connect");
    let ctrl_local_ip = ctrl.local_addr().unwrap().ip();

    let (data_listener, advertise_ip, _port) = bind_active_listener(Some(ctrl_local_ip))
        .expect("bind active listener");
    assert!(advertise_ip.is_ipv6(), "must advertise IPv6");
    assert!(
        data_listener.local_addr().unwrap().is_ipv6(),
        "listener family must match the control connection"
    );
    handle.join().unwrap();
}

#[test]
fn unknown_control_local_ip_falls_back_to_ipv4() {
    // No local address known (e.g. proxied control channel) → legacy
    // IPv4 wildcard behavior, at least with a correct port.
    let (_data_listener, advertise_ip, _port) =
        bind_active_listener(None).expect("bind active listener");
    assert!(advertise_ip.is_ipv4());
}

// ============================================================================
// End-to-end: mock FTP server verifies the PORT command payload
// ============================================================================

#[test]
fn ftp_active_mode_port_command_advertises_control_ip() {
    // Mock FTP server: captures the PORT command parameters and completes
    // the session. The client downloads a small file in active mode; the
    // test then asserts the PORT parameters advertise 127.0.0.1, not 0.0.0.0.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
        let mut port_cmd: Option<String> = None;

        s.write_all(b"220 mock ready\r\n").unwrap();
        loop {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = s.read(&mut byte).unwrap();
                if n == 0 {
                    return port_cmd;
                }
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
            let upper = line.split(' ').next().unwrap_or("").to_uppercase();
            match upper.as_str() {
                "USER" => s.write_all(b"331 need pass\r\n").unwrap(),
                "PASS" => s.write_all(b"230 ok\r\n").unwrap(),
                "TYPE" => s.write_all(b"200 ok\r\n").unwrap(),
                "PORT" => {
                    port_cmd = Some(line.clone());
                    s.write_all(b"200 ok\r\n").unwrap();
                }
                "RETR" => {
                    s.write_all(b"550 not sent (active mode rejected)\r\n").unwrap();
                    return port_cmd;
                }
                "QUIT" => {
                    s.write_all(b"221 bye\r\n").unwrap();
                    return port_cmd;
                }
                _ => s.write_all(b"502 unknown\r\n").unwrap(),
            }
        }
    });

    // Client: FtpClient with active mode (--no-passive-ftp).
    let mut client = ut_ftp::FtpClient::new().with_passive(false);
    client.connect("127.0.0.1", port).expect("connect");
    client.login("u", "p").expect("login");
    client.type_binary().expect("TYPE");

    let mut out = Vec::new();
    // RETR is refused by the mock (550) — we only care about the PORT cmd.
    let _ = client.retr("file.bin", &mut out, None);
    let _ = client.quit();

    let port_cmd = server.join().unwrap();
    let port_cmd = port_cmd.expect("server must receive a PORT command");
    // PORT h1,h2,h3,h4,p1,p2 — h1..h4 must be 127,0,0,1
    let args = port_cmd.split(' ').nth(1).expect("PORT has arguments");
    let octets: Vec<&str> = args.split(',').collect();
    assert_eq!(octets.len(), 6, "PORT takes 6 octets: {}", port_cmd);
    assert_eq!(
        (octets[0], octets[1], octets[2], octets[3]),
        ("127", "0", "0", "1"),
        "PORT must advertise the control connection's IP 127.0.0.1, got {}",
        port_cmd
    );
}
