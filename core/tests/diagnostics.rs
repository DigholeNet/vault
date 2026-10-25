// SPDX-License-Identifier: MIT
use std::net::IpAddr;
use vault_core::diagnostics::{wire::*, *};

fn config() -> Config {
    Config {
        session_id: 42,
        domains: vec!["example.com".into()],
        dns_servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        tunnel_ipv4: Some("10.0.0.2".parse().unwrap()),
        tunnel_ipv4_prefix: Some(24),
        tunnel_ipv6: Some("fd00::2".parse().unwrap()),
        ..Config::default()
    }
}

fn success(request: &Request) -> Observation {
    match request.operation {
        Operation::Route => Observation::Route {
            ipv4: Some("10.0.0.2".parse().unwrap()),
            ipv6: Some("fd00::2".parse().unwrap()),
        },
        Operation::Dns { ipv6, .. } => Observation::Dns {
            addresses: vec![
                if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
                    .parse()
                    .unwrap(),
            ],
        },
        Operation::Tcp { .. } => Observation::Tcp,
        Operation::Https { .. } => Observation::Https {
            status_line: "HTTP/1.1 200 OK".into(),
            received_bytes: 128,
            tls_duration_ms: 2,
            certificate: "example certificate".into(),
        },
        Operation::Ping { .. } => Observation::Ping { rtt_ms: 4 },
    }
}

fn failed() -> Observation {
    Observation::Failed(Failure {
        kind: ErrorKind::Timeout,
        detail: "timeout".into(),
    })
}

fn drive(
    engine: &mut Engine,
    now: &mut u64,
    mut observe: impl FnMut(&Request) -> Observation,
) -> Vec<Request> {
    let mut requests = vec![];
    while let Some(request) = engine.next_request(*now).unwrap() {
        let observation = observe(&request);
        *now += 10;
        engine.complete(request.id, observation, *now).unwrap();
        requests.push(request);
        assert!(requests.len() < 200);
    }
    requests
}

#[test]
fn suite_order() {
    let mut engine = Engine::new(config(), 100).unwrap();
    let requests = drive(&mut engine, &mut 100, success);
    assert_eq!(
        requests.iter().map(|r| r.stage).collect::<Vec<_>>(),
        vec![
            Stage::Route,
            Stage::Dns,
            Stage::Tcp,
            Stage::Https,
            Stage::Dns6,
            Stage::Tcp6,
            Stage::Https6,
            Stage::Gateway,
            Stage::Gateway,
            Stage::Gateway,
            Stage::Gateway,
            Stage::Gateway,
            Stage::Gateway,
            Stage::Application,
            Stage::Ping,
            Stage::Ping,
            Stage::Ping6,
            Stage::Ping6
        ]
    );
    for r in &requests {
        assert_eq!(r.session_id, 42);
        match r.stage {
            Stage::Route | Stage::Application | Stage::Ping | Stage::Ping6 => {
                assert_eq!(r.scope, Scope::Application)
            }
            Stage::Gateway => assert_eq!(r.scope, Scope::HostDefault),
            _ => assert_eq!(r.scope, Scope::Tunnel),
        }
        if matches!(r.stage, Stage::Https | Stage::Https6) {
            assert!(matches!(
                r.operation,
                Operation::Https {
                    address: Some(_),
                    ..
                }
            ));
        }
    }
    let result = engine.snapshot();
    assert!(!result.running);
    assert_eq!(result.state, State::Passed);
    assert_eq!(result.checks.len(), 9);
    assert_eq!(result.domain_states["example.com"], State::Passed);
}

#[test]
fn candidate_fallback() {
    let mut engine = Engine::new(config(), 0).unwrap();
    drive(&mut engine, &mut 0, |r| match r.operation {
        Operation::Dns { server, .. } if server.to_string() == "1.1.1.1" => failed(),
        Operation::Dns { ipv6: false, .. } => Observation::Dns {
            addresses: vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
        },
        Operation::Tcp { address, .. } if address.to_string() == "192.0.2.1" => failed(),
        _ => success(r),
    });
    let result = engine.snapshot();
    assert_eq!(result.state, State::Passed);
    assert_eq!(result.domain_states["example.com"], State::Passed);
    let tcp = result
        .checks
        .iter()
        .find(|c| c.stage == Stage::Tcp)
        .unwrap();
    assert_eq!((tcp.passed, tcp.attempted, tcp.sample_count), (1, 1, 2));
    assert_eq!(result.probes.iter().filter(|p| !p.succeeded).count(), 3);
}

#[test]
fn ping_reply_average() {
    let mut engine = Engine::new(config(), 0).unwrap();
    drive(&mut engine, &mut 0, |r| {
        if matches!(r.stage, Stage::Ping | Stage::Ping6)
            && matches!(r.operation, Operation::Ping { sequence: 1, .. })
        {
            failed()
        } else {
            success(r)
        }
    });
    let result = engine.snapshot();
    assert_eq!(result.state, State::Passed);
    let ping = result
        .checks
        .iter()
        .find(|c| c.stage == Stage::Ping)
        .unwrap();
    assert_eq!(
        (
            ping.passed,
            ping.attempted,
            ping.sample_count,
            ping.duration_ms
        ),
        (1, 2, 1, 4)
    );
    assert_eq!(ping.state, State::Incomplete);
}

#[test]
fn missing_ipv6() {
    let mut cfg = config();
    cfg.tunnel_ipv6 = None;
    let mut engine = Engine::new(cfg, 0).unwrap();
    let requests = drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Route {
            Observation::Route {
                ipv4: Some("10.0.0.2".parse().unwrap()),
                ipv6: None,
            }
        } else {
            success(r)
        }
    });
    assert!(
        !requests
            .iter()
            .any(|r| matches!(r.stage, Stage::Dns6 | Stage::Tcp6 | Stage::Https6))
    );
    assert_eq!(engine.snapshot().state, State::Incomplete);
}

#[test]
fn no_aaaa_skip() {
    let mut cfg = config();
    cfg.domains.push("other.example".into());
    let mut engine = Engine::new(cfg, 0).unwrap();
    let requests = drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Dns6 && r.domain == "example.com" {
            Observation::Dns { addresses: vec![] }
        } else {
            success(r)
        }
    });
    assert!(
        !requests
            .iter()
            .any(|r| r.domain == "example.com" && matches!(r.stage, Stage::Tcp6 | Stage::Https6))
    );
    assert_eq!(engine.snapshot().state, State::Passed);
    assert_eq!(
        engine.snapshot().domain_states["example.com"],
        State::Passed
    );
}

#[test]
fn no_ipv6_targets() {
    let mut engine = Engine::new(config(), 0).unwrap();
    drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Dns6 {
            Observation::Dns { addresses: vec![] }
        } else {
            success(r)
        }
    });
    assert_eq!(engine.snapshot().state, State::Incomplete);
    assert_eq!(
        engine.snapshot().domain_states["example.com"],
        State::Passed
    );
}

#[test]
fn late_response() {
    let mut engine = Engine::new(config(), 0).unwrap();
    let mut now = 0;
    let mut saw_ipv6 = false;
    while let Some(r) = engine.next_request(now).unwrap() {
        if matches!(r.stage, Stage::Dns | Stage::Tcp | Stage::Https) {
            now = r.deadline_ms;
        } else {
            now += 10;
            saw_ipv6 |= r.stage == Stage::Dns6;
        }
        engine.complete(r.id, success(&r), now).unwrap();
    }
    assert!(saw_ipv6);
    let result = engine.snapshot();
    assert_eq!(result.state, State::Incomplete); // downstream IPv4 stages unmeasured
    assert!(
        result
            .probes
            .iter()
            .filter(|p| p.request.stage == Stage::Dns)
            .all(|p| matches!(
                p.observation,
                Observation::Failed(Failure {
                    kind: ErrorKind::Timeout,
                    ..
                })
            ))
    );
    assert!(
        result
            .checks
            .iter()
            .any(|c| c.stage == Stage::Https6 && c.state == State::Passed)
    );
}

#[test]
fn invalid_responses() {
    let mut engine = Engine::new(config(), 0).unwrap();
    let request = engine.next_request(0).unwrap().unwrap();
    assert_eq!(engine.next_request(0), Err(EngineError::ResponsePending));
    assert_eq!(
        engine.complete(request.id + 1, success(&request), 1),
        Err(EngineError::StaleResponse)
    );
    assert_eq!(
        engine.complete(request.id, Observation::Tcp, 2),
        Err(EngineError::WrongObservation)
    );
    engine.cancel(3).unwrap();
    assert_eq!(
        engine.complete(request.id, success(&request), 4),
        Err(EngineError::StaleResponse)
    );
    assert!(engine.next_request(4).unwrap().is_none());
    assert!(engine.snapshot().probes.is_empty());
    assert!(engine.snapshot().cancelled);
    assert_eq!(engine.snapshot().state, State::Incomplete);
    assert_eq!(engine.next_request(3), Err(EngineError::ClockWentBackwards));
}

#[test]
fn malformed_results() {
    let mut engine = Engine::new(config(), 0).unwrap();
    drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Https {
            Observation::Https {
                status_line: "HTTP/1.1 100 Continue".into(),
                received_bytes: 32,
                tls_duration_ms: 1,
                certificate: String::new(),
            }
        } else {
            success(r)
        }
    });
    assert_eq!(engine.snapshot().state, State::Failed);
    let mut engine = Engine::new(config(), 0).unwrap();
    drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Dns {
            Observation::Dns {
                addresses: vec!["::1".parse().unwrap()],
            }
        } else {
            success(r)
        }
    });
    assert_ne!(engine.snapshot().state, State::Passed);
}

#[test]
fn route_bypass() {
    let mut engine = Engine::new(config(), 0).unwrap();
    drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Route {
            Observation::Route {
                ipv4: Some("192.168.1.2".parse().unwrap()),
                ipv6: Some("fd00::2".parse().unwrap()),
            }
        } else {
            success(r)
        }
    });
    assert_eq!(engine.snapshot().state, State::Failed);
    let mut cfg = config();
    cfg.tunnel_ipv6 = None;
    assert_eq!(
        assess_routes(
            &cfg,
            Some("10.0.0.2".parse().unwrap()),
            Some("2001:db8::1".parse().unwrap())
        )
        .issues
        .len(),
        1
    );
    cfg.tunnel_ipv4 = None;
    assert!(assess_routes(&cfg, None, None).issues.is_empty());
    assert!(!assess_routes(&cfg, None, None).unavailable.is_empty());
}

#[test]
fn config_validation() {
    let mut cfg = config();
    cfg.domains = vec![" EXAMPLE.com. ".into(), "example.com".into()];
    assert_eq!(
        Engine::new(cfg, 0).unwrap().snapshot().domains,
        vec!["example.com"]
    );
    assert_eq!(
        Engine::new(Config::default(), 0)
            .unwrap()
            .snapshot()
            .domains
            .len(),
        3
    );
    for domain in [
        "",
        "https://example.com",
        "a..com",
        "-a.com",
        "a\r\nHost: x",
        "中文.com",
    ] {
        let mut cfg = config();
        cfg.domains = vec![domain.into()];
        assert!(Engine::new(cfg, 0).is_err(), "{domain}");
    }
    let mut cfg = config();
    cfg.tunnel_mtu = 1500;
    assert!(Engine::new(cfg, 0).is_err());
}

#[test]
fn dns_validation() {
    let query = dns_query("example.com", 123, false).unwrap();
    let mut response = query.clone();
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 1;
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
    assert_eq!(
        dns_answers(&response, "example.com", 123, false).unwrap(),
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        dns_answers(&response, "example.com", 124, false),
        Err(WireError::WrongTransaction)
    );
    assert_eq!(
        dns_answers(&response, "other.example", 123, false),
        Err(WireError::Malformed)
    );
    response[2] |= 2;
    assert_eq!(
        dns_answers(&response, "example.com", 123, false),
        Err(WireError::Truncated)
    );
    response[2] &= !2;
    let answer_offset = query.len();
    response[answer_offset + 1] = answer_offset as u8;
    assert_eq!(
        dns_answers(&response, "example.com", 123, false),
        Err(WireError::Malformed)
    );
    for size in 0..query.len() {
        assert!(dns_answers(&query[..size], "example.com", 123, false).is_err());
    }
    assert!(dns_query("bad\r\nname", 0, false).is_err());
}

#[test]
fn dns_empty_aaaa() {
    let mut response = dns_query("example.com", 7, true).unwrap();
    response[2] = 0x81;
    response[3] = 0x80;
    assert_eq!(dns_answers(&response, "example.com", 7, true), Ok(vec![]));
    response[3] = 0x83;
    assert_eq!(
        dns_answers(&response, "example.com", 7, true),
        Err(WireError::DnsResponse(3))
    );
}

#[test]
fn http_framing() {
    assert_eq!(
        http_status(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", true),
        Ok("HTTP/1.1 200 OK".into())
    );
    assert_eq!(
        http_status(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK", true),
        Err(WireError::Truncated)
    );
    assert!(
        http_status(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
            true
        )
        .is_ok()
    );
    assert!(
        http_status(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nO",
            true
        )
        .is_err()
    );
    assert!(http_status(b"HTTP/1.1 100 Continue\r\n\r\n", true).is_err());
    assert!(http_status(b"HTTP/1.1 204 No Content\r\n\r\n", true).is_ok());
    let mut sample = b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n".to_vec();
    sample.resize(65536, b'x');
    assert!(http_status(&sample, false).is_ok());
    assert!(http_status(&sample, true).is_err());
    assert!(
        String::from_utf8(https_request("example.com").unwrap())
            .unwrap()
            .starts_with("GET / HTTP/1.1\r\nHost: example.com\r\nRange:")
    );
}

#[test]
fn checksum_roundtrip() {
    let mut packet = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, 9];
    let sum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(icmp_checksum(&packet), 0);
}

#[test]
fn pending_timeout() {
    let mut engine = Engine::new(config(), 0).unwrap();
    let old = engine.next_request(0).unwrap().unwrap();
    let next = engine.next_request(old.deadline_ms).unwrap().unwrap();
    assert_ne!(next.id, old.id);
    assert_eq!(
        engine.complete(old.id, success(&old), old.deadline_ms),
        Err(EngineError::StaleResponse)
    );
    assert!(!engine.snapshot().routes.unavailable.is_empty());
}

#[test]
fn gateway_baseline() {
    let mut engine = Engine::new(config(), 0).unwrap();
    let requests = drive(&mut engine, &mut 0, |r| {
        if r.stage == Stage::Gateway {
            failed()
        } else {
            success(r)
        }
    });
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.stage == Stage::Gateway)
            .count(),
        2
    );
    assert_eq!(engine.snapshot().state, State::Passed);
}

#[test]
fn duration_freezes() {
    let mut engine = Engine::new(config(), 0).unwrap();
    let mut now = 0;
    drive(&mut engine, &mut now, success);
    let duration = engine.snapshot().duration_ms;
    assert!(engine.next_request(now + 1000).unwrap().is_none());
    assert_eq!(engine.snapshot().duration_ms, duration);
}

#[test]
fn dns_aliases() {
    let mut response = dns_query("example.com", 1, false).unwrap();
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 3;
    // example.com CNAME alias.example.com (compressed suffix)
    response.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8]);
    let alias_offset = response.len() as u8;
    response.extend_from_slice(&[5, b'a', b'l', b'i', b'a', b's', 0xc0, 12]);
    response.extend_from_slice(&[
        0xc0,
        alias_offset,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        60,
        0,
        4,
        192,
        0,
        2,
        1,
    ]);
    response.extend_from_slice(&[
        4, b'e', b'v', b'i', b'l', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9,
    ]);
    assert_eq!(
        dns_answers(&response, "example.com", 1, false).unwrap(),
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
    let mut response = dns_query("example.com", 2, true).unwrap();
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 1;
    response.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
    response.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert_eq!(
        dns_answers(&response, "example.com", 2, true).unwrap(),
        vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn ipv6_budget() {
    let mut cfg = config();
    cfg.domains = (0..6).map(|n| format!("target{n}.example")).collect();
    let mut engine = Engine::new(cfg, 0).unwrap();
    let mut now = 0;
    let mut ipv6_start = None;
    while let Some(r) = engine.next_request(now).unwrap() {
        let response = if r.stage == Stage::Dns {
            now = r.deadline_ms;
            failed()
        } else {
            if r.stage == Stage::Dns6 {
                ipv6_start.get_or_insert(now);
            }
            now += 10;
            success(&r)
        };
        engine.complete(r.id, response, now).unwrap();
    }
    assert_eq!(ipv6_start, Some(25_010));
    let snapshot = engine.snapshot();
    assert!(
        snapshot
            .checks
            .iter()
            .any(|c| c.stage == Stage::Dns && c.state == State::Incomplete)
    );
    assert!(
        snapshot
            .checks
            .iter()
            .any(|c| c.stage == Stage::Https6 && c.state == State::Passed && c.passed == 6)
    );
}

#[test]
fn application_budget() {
    let mut cfg = config();
    cfg.domains = (0..6).map(|n| format!("target{n}.example")).collect();
    let mut engine = Engine::new(cfg, 0).unwrap();
    let mut now = 0;
    let mut app_requests = 0;
    let mut ping_requests = 0;
    while let Some(r) = engine.next_request(now).unwrap() {
        if r.stage == Stage::Application {
            app_requests += 1;
            now = r.deadline_ms;
        } else {
            ping_requests += usize::from(matches!(r.stage, Stage::Ping | Stage::Ping6));
            now += 10;
        }
        engine.complete(r.id, success(&r), now).unwrap();
    }
    assert_eq!(app_requests, 3);
    assert_eq!(ping_requests, 4);
    assert_eq!(engine.snapshot().state, State::Incomplete);
}

#[test]
fn route_metadata() {
    let mut cfg = config();
    let v4 = Some("10.0.0.2".parse().unwrap());
    let v6 = Some("fd00:0:0:0:0:0:0:2".parse().unwrap());
    assert_eq!(assess_routes(&cfg, v4, v6), RouteAssessment::default());
    assert_eq!(assess_routes(&cfg, None, None).unavailable.len(), 2);
    cfg.tunnel_ipv4 = None;
    let partial = assess_routes(&cfg, v4, v6);
    assert!(partial.issues.is_empty());
    assert_eq!(partial.unavailable.len(), 1);
    let mismatch = assess_routes(&cfg, v4, Some("fd00::3".parse().unwrap()));
    assert_eq!(mismatch.issues.len(), 1);
    cfg.tunnel_ipv6 = None;
    assert!(assess_routes(&cfg, v4, v6).issues.is_empty());
}

#[test]
fn retry_timing() {
    let mut engine = Engine::new(config(), 0).unwrap();
    let route = engine.next_request(0).unwrap().unwrap();
    engine.complete(route.id, success(&route), 10).unwrap();
    let first = engine.next_request(10).unwrap().unwrap();
    engine.complete(first.id, failed(), 40).unwrap();
    let second = engine.next_request(40).unwrap().unwrap();
    engine.complete(second.id, success(&second), 110).unwrap();
    engine.next_request(110).unwrap();
    let check = &engine.snapshot().checks[0];
    assert_eq!(
        (
            check.passed,
            check.attempted,
            check.sample_count,
            check.duration_ms
        ),
        (1, 1, 2, 50)
    );
}
