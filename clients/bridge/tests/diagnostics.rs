// SPDX-License-Identifier: MIT
use vault_bridge::diagnostics::*;

fn config() -> DiagnosticConfig {
    DiagnosticConfig {
        session_id: 7,
        domains: vec!["example.com".into()],
        dns_servers: vec![],
        tunnel_ipv4: Some("10.0.0.2".into()),
        tunnel_ipv4_prefix: Some(24),
        tunnel_ipv6: Some("fd00::2".into()),
        tunnel_mtu: 1427,
    }
}

#[test]
fn suite() {
    let engine = DiagnosticEngine::new(config()).unwrap();
    let mut count = 0;
    while let Some(request) = engine.next_request().unwrap() {
        assert_eq!(request.session_id, 7);
        assert!(request.deadline_ms > engine.elapsed_ms());
        let response = match request.operation {
            DiagnosticOperation::Route => DiagnosticResponse::Route {
                ipv4: Some("10.0.0.2".into()),
                ipv6: Some("fd00::2".into()),
            },
            DiagnosticOperation::Dns { ipv6, .. } => DiagnosticResponse::Dns {
                addresses: vec![if ipv6 { "2001:db8::1" } else { "192.0.2.1" }.into()],
            },
            DiagnosticOperation::Tcp { .. } => DiagnosticResponse::Tcp,
            DiagnosticOperation::Https { .. } => DiagnosticResponse::Https {
                status_line: "HTTP/1.1 200 OK".into(),
                received_bytes: 40,
                tls_duration_ms: 0,
                certificate: "trusted certificate".into(),
            },
            DiagnosticOperation::Ping { .. } => DiagnosticResponse::Failed {
                kind: DiagnosticErrorKind::Permission,
                detail: "ICMP unavailable".into(),
            },
        };
        engine.complete(request.id, response).unwrap();
        count += 1;
        assert!(count < 30);
    }
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.state, DiagnosticState::Passed);
    assert_eq!(snapshot.checks.len(), 9);
    assert_eq!(snapshot.domain_states[0].state, DiagnosticState::Passed);
    assert!(
        snapshot
            .probes
            .iter()
            .any(|p| p.error_kind == Some(DiagnosticErrorKind::Permission))
    );
    assert!(snapshot.probes.iter().any(|p| p.tls_duration_ms == Some(0)));
}

#[test]
fn cancel_and_validation() {
    let engine = DiagnosticEngine::new(config()).unwrap();
    let request = engine.next_request().unwrap().unwrap();
    engine.cancel().unwrap();
    assert!(
        engine
            .complete(request.id, DiagnosticResponse::Tcp)
            .is_err()
    );
    assert!(engine.snapshot().cancelled);
    assert!(engine.next_request().unwrap().is_none());
    let mut cfg = config();
    cfg.tunnel_ipv4 = Some("hostname.example".into());
    assert!(DiagnosticEngine::new(cfg).is_err());
}

#[test]
fn transport_cancel() {
    let transport = DiagnosticTransport::new(None).unwrap();
    transport.cancel();
    let result = transport
        .execute(
            DiagnosticOperation::Ping {
                address: "127.0.0.1".into(),
                sequence: 1,
                packet_size: 64,
            },
            String::new(),
            1000,
        )
        .unwrap();
    assert!(matches!(
        result,
        DiagnosticResponse::Failed {
            kind: DiagnosticErrorKind::Unavailable,
            ..
        }
    ));
    assert!(DiagnosticTransport::new(Some("hostname.example".into())).is_err());
}
