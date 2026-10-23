//
//  DNSPacketTests.swift
//  VaultCore
//
//
//  Tests for the DNS wire codec used by TunnelDiagnostics: query
//  construction, answer extraction, compression pointers, and malformed
//  packet handling.
//

import Foundation
import Testing

@testable import VaultCore

@Test func buildQueryEncodesHeaderAndQuestion() {
    let query = DNSPacket.buildQuery(domain: "github.com", id: 0x1234)
    #expect(query != nil)
    guard let bytes = query.map(Array.init) else { return }

    #expect(bytes[0] == 0x12 && bytes[1] == 0x34) // ID
    #expect(bytes[2] == 0x01 && bytes[3] == 0x00) // RD
    #expect(bytes[4] == 0x00 && bytes[5] == 0x01) // QDCOUNT
    #expect(bytes[6...11].allSatisfy { $0 == 0 })

    // QNAME: 6 "github" 3 "com" 0, then QTYPE/QCLASS.
    let qname: [UInt8] = [6] + Array("github".utf8) + [3] + Array("com".utf8) + [0]
    #expect(Array(bytes[12..<(12 + qname.count)]) == qname)
    #expect(Array(bytes.suffix(4)) == [0x00, 0x01, 0x00, 0x01])
}

@Test func buildQueryRejectsBadDomains() {
    #expect(DNSPacket.buildQuery(domain: "", id: 1) == nil)
    #expect(DNSPacket.buildQuery(domain: String(repeating: "a", count: 64) + ".com", id: 1) == nil)
    #expect(DNSPacket.buildQuery(domain: "héxample.com", id: 1) == nil)
    #expect(DNSPacket.buildQuery(domain: "one.two..three", id: 1) != nil) // empty labels dropped
}

/// Builds a minimal response: header + echoed question + one answer whose
/// name is a compression pointer back to the question.
private func response(id: UInt16, rcode: UInt8 = 0, ips: [String]) -> Data {
    var data = DNSPacket.buildQuery(domain: "example.com", id: id)!
    // Flip QR, set rcode, ANCOUNT = ips.count.
    data[2] = 0x81
    data[3] = 0x80 | rcode
    data[6] = UInt8(ips.count >> 8)
    data[7] = UInt8(ips.count & 0xff)
    for ip in ips {
        let parts = ip.split(separator: ".").map { UInt8($0)! }
        data.append(contentsOf: [0xc0, 0x0c]) // pointer to the question name
        data.append(contentsOf: [0x00, 0x01]) // TYPE A
        data.append(contentsOf: [0x00, 0x01]) // CLASS IN
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x3c]) // TTL 60
        data.append(contentsOf: [0x00, 0x04]) // RDLENGTH
        data.append(contentsOf: parts)
    }
    return data
}

@Test func parseAnswersExtractsARecords() {
    let data = response(id: 7, ips: ["140.82.116.3", "1.2.3.4"])
    #expect(DNSPacket.parseAnswers(data, expectedID: 7) == ["140.82.116.3", "1.2.3.4"])
}

@Test func parseAnswersAcceptsEmptyAnswerSection() {
    let data = response(id: 7, ips: [])
    #expect(DNSPacket.parseAnswers(data, expectedID: 7) == [])
}

@Test func parseAnswersRejectsMismatchesAndErrors() {
    #expect(DNSPacket.parseAnswers(response(id: 7, ips: ["1.1.1.1"]), expectedID: 8) == nil)
    #expect(DNSPacket.parseAnswers(response(id: 7, rcode: 3, ips: []), expectedID: 7) == nil)
    #expect(DNSPacket.parseAnswers(Data([0x00, 0x01]), expectedID: 7) == nil)

    // Truncated mid-answer.
    var truncated = response(id: 7, ips: ["1.1.1.1"])
    truncated.removeLast(3)
    #expect(DNSPacket.parseAnswers(truncated, expectedID: 7) == nil)
}

@Test func parseAnswersFollowsNameLabelsWithoutPointers() {
    // Answer with a full (uncompressed) name instead of a pointer.
    var data = DNSPacket.buildQuery(domain: "example.com", id: 9)!
    data[2] = 0x81
    data[3] = 0x80
    data[6] = 0x00
    data[7] = 0x01
    data.append(contentsOf: [7] + "example".utf8 + [3] + "com".utf8 + [0])
    data.append(contentsOf: [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04])
    data.append(contentsOf: [9, 8, 7, 6])
    #expect(DNSPacket.parseAnswers(data, expectedID: 9) == ["9.8.7.6"])
}

@Test func icmpChecksumMatchesKnownVector() {
    // RFC 1071 example style: checksum of a known echo request.
    // type=8 code=0 csum=0 id=0x0001 seq=0x0001 payload "abcdefgh"
    let message: [UInt8] = [8, 0, 0, 0, 0, 1, 0, 1] + Array("abcdefgh".utf8)
    let sum = TunnelDiagnostics.icmpChecksum(message)
    // Recomputing over the message with the checksum inserted must yield 0.
    var withSum = message
    withSum[2] = UInt8(sum >> 8)
    withSum[3] = UInt8(sum & 0xff)
    #expect(TunnelDiagnostics.icmpChecksum(withSum) == 0xffff || TunnelDiagnostics.icmpChecksum(withSum) == 0x0000)
    // An odd-length buffer must not crash or read out of bounds.
    _ = TunnelDiagnostics.icmpChecksum([8, 0, 0, 0, 0])
}

@Test func gatewayAddressIsNetworkPlusOne() {
    #expect(TunnelDiagnostics.gatewayAddress(ip: "192.168.10.2", mask: "255.255.255.0") == "192.168.10.1")
    #expect(TunnelDiagnostics.gatewayAddress(ip: "10.2.3.4", mask: "255.255.0.0") == "10.2.0.1")
    #expect(TunnelDiagnostics.gatewayAddress(ip: "not-an-ip", mask: "255.255.255.0") == nil)
    #expect(TunnelDiagnostics.gatewayAddress(ip: "192.168.10.2", mask: "0.0.0.0") == nil)
}
