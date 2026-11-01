// SPDX-License-Identifier: MIT
//! Bounded DNS/HTTP parsers shared by platform transports. No resolver or TLS
//! implementation is selected here: transport binding and trust remain explicit.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidDomain,
    Malformed,
    WrongTransaction,
    Truncated,
    DnsResponse(u8),
}

pub fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// One IN question with recursion desired. `ipv6` selects AAAA instead of A.
pub fn dns_query(domain: &str, id: u16, ipv6: bool) -> Result<Vec<u8>, WireError> {
    if !valid_domain(domain) {
        return Err(WireError::InvalidDomain);
    }
    let mut bytes = Vec::with_capacity(domain.len() + 18);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in domain.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&(if ipv6 { 28u16 } else { 1u16 }).to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    Ok(bytes)
}

fn word(bytes: &[u8], offset: usize) -> Result<u16, WireError> {
    let b = bytes.get(offset..offset + 2).ok_or(WireError::Malformed)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Decode compressed names with bounded traversal; pointers must point backward.
fn name(bytes: &[u8], offset: &mut usize) -> Result<String, WireError> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let count = *bytes.get(cursor).ok_or(WireError::Malformed)?;
        if count & 0xc0 == 0xc0 {
            let ptr = (word(bytes, cursor)? & 0x3fff) as usize;
            if ptr >= cursor {
                return Err(WireError::Malformed);
            }
            if !jumped {
                *offset = cursor + 2;
                jumped = true;
            }
            cursor = ptr;
        } else if count & 0xc0 != 0 {
            return Err(WireError::Malformed);
        } else if count == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(labels.join("."));
        } else {
            cursor += 1;
            let label = bytes
                .get(cursor..cursor + count as usize)
                .ok_or(WireError::Malformed)?;
            length += count as usize + 1;
            if length > 254 {
                return Err(WireError::Malformed);
            }
            labels.push(
                std::str::from_utf8(label)
                    .map_err(|_| WireError::Malformed)?
                    .to_ascii_lowercase(),
            );
            cursor += count as usize;
        }
    }
    Err(WireError::Malformed)
}

/// Validate transaction/question, follow CNAMEs, and return only addresses
/// belonging to the requested name/alias chain (not unrelated answer records).
/// Empty AAAA is a successful DNS observation; callers decide A requirements.
pub fn dns_answers(
    bytes: &[u8],
    domain: &str,
    id: u16,
    ipv6: bool,
) -> Result<Vec<IpAddr>, WireError> {
    if bytes.len() < 12 || bytes.len() > 65535 {
        return Err(WireError::Malformed);
    }
    if word(bytes, 0)? != id {
        return Err(WireError::WrongTransaction);
    }
    let flags = word(bytes, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Err(WireError::Malformed);
    }
    if flags & 0x0200 != 0 {
        return Err(WireError::Truncated);
    }
    if flags & 0xf != 0 {
        return Err(WireError::DnsResponse((flags & 0xf) as u8));
    }
    if word(bytes, 4)? != 1 {
        return Err(WireError::Malformed);
    }
    let mut offset = 12;
    if name(bytes, &mut offset)? != domain.to_ascii_lowercase()
        || word(bytes, offset)? != if ipv6 { 28 } else { 1 }
        || word(bytes, offset + 2)? != 1
    {
        return Err(WireError::Malformed);
    }
    offset += 4;
    let mut aliases = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..word(bytes, 6)? {
        let owner = name(bytes, &mut offset)?;
        let kind = word(bytes, offset)?;
        let class = word(bytes, offset + 2)?;
        let len = word(bytes, offset + 8)? as usize;
        offset += 10;
        let data = bytes
            .get(offset..offset + len)
            .ok_or(WireError::Malformed)?;
        if class == 1 {
            if kind == 5 {
                let mut end = offset;
                let alias = name(bytes, &mut end)?;
                if end != offset + len {
                    return Err(WireError::Malformed);
                }
                aliases.push((owner.clone(), alias));
            } else if kind == 1 && !ipv6 {
                let octets: [u8; 4] = data.try_into().map_err(|_| WireError::Malformed)?;
                addresses.push((owner, IpAddr::V4(Ipv4Addr::from(octets))));
            } else if kind == 28 && ipv6 {
                let octets: [u8; 16] = data.try_into().map_err(|_| WireError::Malformed)?;
                addresses.push((owner, IpAddr::V6(Ipv6Addr::from(octets))));
            }
        }
        offset += len;
    }
    let mut accepted = std::collections::BTreeSet::from([domain.to_ascii_lowercase()]);
    for _ in 0..aliases.len() {
        let before = accepted.len();
        for (from, to) in &aliases {
            if accepted.contains(from) {
                accepted.insert(to.clone());
            }
        }
        if before == accepted.len() {
            break;
        }
    }
    let mut result = Vec::new();
    for (owner, address) in addresses {
        if accepted.contains(&owner) && !result.contains(&address) {
            result.push(address);
        }
    }
    Ok(result)
}

pub fn valid_status_line(line: &str) -> bool {
    let mut parts = line.splitn(3, ' ');
    matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        && parts.next().is_some_and(|code| {
            code.len() == 3
                && code.bytes().all(|b| b.is_ascii_digit())
                && code.parse::<u16>().is_ok_and(|n| (200..=599).contains(&n))
        })
        && !line.bytes().any(|b| b < 32 || b == 127)
}

/// The same bounded HTTP/1.1 GET for fixed-IP tunnel and app-route probes.
pub fn https_request(domain: &str) -> Result<Vec<u8>, WireError> {
    if !valid_domain(domain) {
        return Err(WireError::InvalidDomain);
    }
    Ok(format!(
        "GET / HTTP/1.1\r\nHost: {domain}\r\nRange: bytes=0-65535\r\nConnection: close\r\n\r\n"
    )
    .into_bytes())
}

/// Validate the bounded response sample. On EOF reject truncated bodies;
/// at the 64KiB sample limit a complete body is intentionally not required.
pub fn http_status(bytes: &[u8], eof: bool) -> Result<String, WireError> {
    if bytes.len() > 65536 {
        return Err(WireError::Malformed);
    }
    let split = bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or(WireError::Malformed)?;
    let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| WireError::Malformed)?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or(WireError::Malformed)?;
    if !valid_status_line(status) {
        return Err(WireError::Malformed);
    }
    let body = &bytes[split + 4..];
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (key, value) = line.split_once(':').ok_or(WireError::Malformed)?;
        if key.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| WireError::Malformed)?;
            if length.is_some_and(|n| n != parsed) {
                return Err(WireError::Malformed);
            }
            length = Some(parsed);
        }
        if key.eq_ignore_ascii_case("transfer-encoding") {
            chunked |= value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    let code = &status[9..12];
    if eof && code != "204" && code != "304" {
        if chunked {
            complete_chunks(body)?;
        } else if length.is_some_and(|n| n != body.len()) {
            return Err(WireError::Truncated);
        }
    } else if !eof && bytes.len() < 65536 {
        return Err(WireError::Truncated);
    }
    Ok(status.to_owned())
}

fn complete_chunks(mut bytes: &[u8]) -> Result<(), WireError> {
    loop {
        let end = bytes
            .windows(2)
            .position(|b| b == b"\r\n")
            .ok_or(WireError::Truncated)?;
        let text = std::str::from_utf8(&bytes[..end]).map_err(|_| WireError::Malformed)?;
        let hex = text.split(';').next().ok_or(WireError::Malformed)?;
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WireError::Malformed);
        }
        let size = usize::from_str_radix(hex, 16).map_err(|_| WireError::Malformed)?;
        bytes = &bytes[end + 2..];
        if size == 0 {
            return if bytes == b"\r\n" || bytes.windows(4).any(|b| b == b"\r\n\r\n") {
                Ok(())
            } else {
                Err(WireError::Truncated)
            };
        }
        if size > bytes.len() || bytes.get(size..size.saturating_add(2)) != Some(b"\r\n") {
            return Err(WireError::Truncated);
        }
        bytes = &bytes[size + 2..];
    }
}

pub fn icmp_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u64 = bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u64)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
