// SPDX-License-Identifier: MIT
//! Explicit remote integration checks. No local HTTPS server, key or trust override.
use std::net::ToSocketAddrs;
use std::time::Duration;
use vault_core::diagnostics::{ErrorKind, Observation, Operation, transport};

#[test]
#[ignore = "requires access to https://example.com"]
fn remote_https() {
    let result = transport::execute(
        &Operation::Https {
            address: None,
            port: 443,
        },
        "example.com",
        Duration::from_secs(20),
        &transport::DefaultNetwork,
        &transport::Cancellation::default(),
    );
    assert!(matches!(result, Observation::Https { .. }), "{result:?}");
    if let Observation::Https {
        status_line,
        received_bytes,
        certificate,
        ..
    } = result
    {
        assert!(status_line.starts_with("HTTP/1.1 ") || status_line.starts_with("HTTP/1.0 "));
        assert!(received_bytes > 0);
        assert!(!certificate.is_empty());
    }
}

#[test]
#[ignore = "requires direct TLS access to example.com"]
fn remote_hostname() {
    let mut result = None;
    for address in ("example.com", 443).to_socket_addrs().unwrap() {
        let attempt = transport::execute(
            &Operation::Https {
                address: Some(address.ip()),
                port: 443,
            },
            "wrong.example",
            Duration::from_secs(10),
            &transport::DefaultNetwork,
            &transport::Cancellation::default(),
        );
        if matches!(attempt, Observation::Failed(ref f) if f.kind == ErrorKind::Tls) {
            result = Some(attempt);
            break;
        }
        result = Some(attempt);
    }
    assert!(
        matches!(result, Some(Observation::Failed(ref f)) if f.kind == ErrorKind::Tls),
        "{result:?}"
    );
}
