// SPDX-License-Identifier: MIT
import Foundation

// MARK: - Cancellation

public final class DiagnosticsCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var cancelled = false
  private var handlers: [UUID: () -> Void] = [:]
  public init() {}
  public func cancel() {
    lock.lock()
    cancelled = true
    let callbacks = Array(handlers.values)
    handlers.removeAll()
    lock.unlock()
    callbacks.forEach { $0() }
  }
  public var isCancelled: Bool {
    lock.lock()
    defer { lock.unlock() }
    return cancelled
  }
  func onCancel(_ action: @escaping () -> Void) -> UUID {
    let id = UUID()
    lock.lock()
    let runNow = cancelled
    if !runNow { handlers[id] = action }
    lock.unlock()
    if runNow { action() }
    return id
  }
  func removeHandler(_ id: UUID) {
    lock.lock()
    handlers.removeValue(forKey: id)
    lock.unlock()
  }
}

// MARK: - UI result models

public struct DiagnosticsCheck: Codable, Sendable, Identifiable {
  public enum State: String, Codable, Sendable { case passed, failed, incomplete }
  public var id: String
  public var passed: Int
  public var attempted: Int
  public var state: State
  /// Mean duration of the sampled requests, in milliseconds.
  public var durationMs: Int
  public var sampleCount: Int

  public init(
    id: String, passed: Int, attempted: Int, state: State, durationMs: Int, sampleCount: Int = 0
  ) {
    self.id = id
    self.passed = passed
    self.attempted = attempted
    self.state = state
    self.durationMs = durationMs
    self.sampleCount = sampleCount
  }
}

public struct DiagnosticsProbe: Codable, Sendable, Identifiable {
  public var id: String
  public var stage: String
  public var domain: String
  public var durationMs: Int
  public var succeeded: Bool
  public var detail: String
  public var tlsDurationMs: Int?

  public init(
    stage: String, domain: String, durationMs: Int, succeeded: Bool, detail: String,
    tlsDurationMs: Int? = nil
  ) {
    self.id = UUID().uuidString
    self.stage = stage
    self.domain = domain
    self.durationMs = durationMs
    self.succeeded = succeeded
    self.detail = detail
    self.tlsDurationMs = tlsDurationMs
  }
}

public struct DiagnosticsResult: Codable, Sendable {
  public var engineState: DiagnosticsCheck.State = .incomplete
  public var domainStates: [String: DiagnosticsCheck.State] = [:]
  public var summary: String
  public var lines: [String]
  public var domains: [String]?
  public var checks: [DiagnosticsCheck]?
  public var durationMs: Int?
  public var activeCheck: String?
  public var probes: [DiagnosticsProbe]?

  public init(
    summary: String, lines: [String], domains: [String]? = nil, checks: [DiagnosticsCheck]? = nil,
    durationMs: Int? = nil, activeCheck: String? = nil, probes: [DiagnosticsProbe]? = nil
  ) {
    self.summary = summary
    self.lines = lines
    self.domains = domains
    self.checks = checks
    self.durationMs = durationMs
    self.activeCheck = activeCheck
    self.probes = probes
  }
}

// MARK: - IPC and Rust engine adapter

/// Live provider configuration. Never construct this from cached AppStorage.
public struct AppleDiagnosticContext: Codable, Sendable {
  public var provider: String
  public var generation: UInt64
  public var connectionGeneration: UInt64
  public var ipv4: String
  public var mask: String
  public var ipv6: String?
  public var mtu: Int
  public var dns: [String]
  public var domains: [String]

  public init(
    provider: String, generation: UInt64, ipv4: String, mask: String,
    ipv6: String?, mtu: Int, dns: [String], domains: [String], connectionGeneration: UInt64 = 0
  ) {
    self.provider = provider
    self.generation = generation
    self.connectionGeneration = connectionGeneration
    self.ipv4 = ipv4
    self.mask = mask
    self.ipv6 = ipv6
    self.mtu = mtu
    self.dns = dns
    self.domains = domains
  }

  public func isSameSession(as other: AppleDiagnosticContext) -> Bool {
    provider == other.provider && generation == other.generation
      && connectionGeneration == other.connectionGeneration
      && ipv4 == other.ipv4 && mask == other.mask && ipv6 == other.ipv6 && mtu == other.mtu
  }

  public func makeEngine() throws -> DiagnosticEngine {
    let bytes = mask.split(separator: ".").compactMap { UInt8($0) }
    let bits = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    let prefix: UInt8? =
      bytes.count == 4 && (bits == 0 || (bits | (bits &- 1)) == UInt32.max)
      ? UInt8(bits.nonzeroBitCount) : nil
    return try DiagnosticEngine(
      config: DiagnosticConfig(
        sessionId: generation,
        domains: domains, dnsServers: dns, tunnelIpv4: ipv4.isEmpty ? nil : ipv4,
        tunnelIpv4Prefix: prefix, tunnelIpv6: ipv6?.isEmpty == false ? ipv6 : nil,
        tunnelMtu: UInt16(clamping: mtu)))
  }
}

/// Codable IPC request for one Rust-selected transport operation.
public struct AppleProbeRequest: Codable, Sendable {
  public enum Operation: Codable, Sendable, Equatable {
    case dns(server: String, ipv6: Bool)
    case tcp(address: String, port: UInt16)
    case https(address: String?)
    case ping(address: String, sequence: UInt16, packetSize: UInt16)
    case route
  }
  public var run: String
  public var provider: String
  public var generation: UInt64
  public var connectionGeneration: UInt64
  public var id: UInt64
  public var domain: String
  public var tunnel: Bool
  public var timeout: TimeInterval
  public var operation: Operation

  /// IPC dispatch and reply delivery must outlive the transport deadline so a
  /// normal probe timeout reaches the engine as a result, not a lost session.
  public var replyTimeout: TimeInterval { timeout + 3 }

  public init(
    request: DiagnosticRequest, context: AppleDiagnosticContext, run: String, remainingMs: UInt64
  ) {
    self.run = run
    provider = context.provider
    generation = context.generation
    connectionGeneration = context.connectionGeneration
    id = request.id
    domain = request.domain
    tunnel = request.scope == .tunnel
    timeout = Double(remainingMs) / 1000
    switch request.operation {
    case .route: operation = .route
    case .dns(let server, let ipv6): operation = .dns(server: server, ipv6: ipv6)
    case .tcp(let address, let port): operation = .tcp(address: address, port: port)
    case .https(let address, _): operation = .https(address: address)
    case .ping(let address, let sequence, let packetSize):
      operation = .ping(address: address, sequence: sequence, packetSize: packetSize)
    }
  }
}

public enum AppleProbeResponse: Codable, Sendable {
  case route(ipv4: String?, ipv6: String?)
  case dns(addresses: [String])
  case tcp
  case https(statusLine: String, receivedBytes: UInt32, tlsMs: UInt64, certificate: String)
  case ping(rttMs: UInt64)
  case failed(kind: DiagnosticErrorKind, detail: String)

  public init(_ value: DiagnosticResponse) {
    switch value {
    case .route(let v4, let v6): self = .route(ipv4: v4, ipv6: v6)
    case .dns(let addresses): self = .dns(addresses: addresses)
    case .tcp: self = .tcp
    case .https(let status, let bytes, let tls, let certificate):
      self = .https(statusLine: status, receivedBytes: bytes, tlsMs: tls, certificate: certificate)
    case .ping(let rtt): self = .ping(rttMs: rtt)
    case .failed(let kind, let detail): self = .failed(kind: kind, detail: detail)
    }
  }

  public var rust: DiagnosticResponse {
    switch self {
    case .route(let v4, let v6): return .route(ipv4: v4, ipv6: v6)
    case .dns(let addresses): return .dns(addresses: addresses)
    case .tcp: return .tcp
    case .https(let status, let bytes, let tls, let cert):
      return .https(statusLine: status, receivedBytes: bytes, tlsDurationMs: tls, certificate: cert)
    case .ping(let rtt): return .ping(rttMs: rtt)
    case .failed(let kind, let detail): return .failed(kind: kind, detail: detail)
    }
  }
}

public struct AppleProbeReply: Codable, Sendable {
  public var run: String
  public var id: UInt64
  public var response: AppleProbeResponse
  public init(request: AppleProbeRequest, response: AppleProbeResponse) {
    run = request.run
    id = request.id
    self.response = response
  }
}

/// Projects typed Rust state into the existing Codable UI model. No verdicts
/// are recomputed from probe strings, candidate failures or stage counts.
public enum RustDiagnostics {
  /// All network execution is Rust-owned. Swift only forwards IPC and cancellation.
  public static func execute(
    _ request: AppleProbeRequest, tunnelIPv4: String?,
    cancellation: DiagnosticsCancellation
  ) -> AppleProbeResponse {
    if request.tunnel && tunnelIPv4 == nil {
      return .failed(kind: .unavailable, detail: "current tunnel address unavailable")
    }
    do {
      let transport = try DiagnosticTransport(tunnelIpv4: request.tunnel ? tunnelIPv4 : nil)
      let token = cancellation.onCancel { transport.cancel() }
      defer { cancellation.removeHandler(token) }
      let operation: DiagnosticOperation
      switch request.operation {
      case .route: operation = .route
      case .dns(let server, let ipv6): operation = .dns(server: server, ipv6: ipv6)
      case .tcp(let address, let port): operation = .tcp(address: address, port: port)
      case .https(let address): operation = .https(address: address, port: 443)
      case .ping(let address, let sequence, let size):
        operation = .ping(address: address, sequence: sequence, packetSize: size)
      }
      let response = try transport.execute(
        operation: operation, domain: request.domain,
        timeoutMs: UInt64(max(0, min(6, request.timeout)) * 1000))
      return AppleProbeResponse(response)
    } catch { return .failed(kind: .unavailable, detail: "\(error)") }
  }

  /// Drives the Rust engine; `execute` dispatches each request to Rust transport.
  /// Must be called on a worker queue. A missing IPC reply invalidates the run.
  public static func run(
    context: AppleDiagnosticContext, cancellation: DiagnosticsCancellation,
    execute: (DiagnosticRequest, UInt64) -> DiagnosticResponse?,
    onProgress: ((DiagnosticsResult) -> Void)? = nil
  ) -> DiagnosticsResult {
    do {
      let engine = try context.makeEngine()
      let token = cancellation.onCancel { try? engine.cancel() }
      defer { cancellation.removeHandler(token) }
      while !cancellation.isCancelled, let request = try engine.nextRequest() {
        onProgress?(result(engine.snapshot()))
        let now = engine.elapsedMs()
        let remaining = request.deadlineMs > now ? request.deadlineMs - now : 0
        guard remaining > 0 else { continue }
        guard let response = execute(request, remaining) else {
          cancellation.cancel()
          break
        }
        if cancellation.isCancelled { break }
        try engine.complete(id: request.id, response: response)
        if let probe = engine.snapshot().probes.last {
          FileLogger.shared.log(
            "[probe] \(probe.request.stage) \(probe.request.domain): \(probe.detail) duration=\(probe.durationMs)ms"
          )
        }
      }
      if cancellation.isCancelled { try? engine.cancel() }
      return result(engine.snapshot())
    } catch {
      return DiagnosticsResult(summary: "INCOMPLETE - Rust diagnostics: \(error)", lines: [])
    }
  }

  public static func result(_ snapshot: DiagnosticSnapshot) -> DiagnosticsResult {
    func state(_ value: DiagnosticState) -> DiagnosticsCheck.State {
      switch value {
      case .passed: return .passed
      case .failed: return .failed
      case .incomplete: return .incomplete
      }
    }
    let probes = snapshot.probes.map { observation in
      let target: String
      switch observation.request.operation {
      case .dns(let server, _): target = "\(server): "
      case .tcp(let address, let port): target = "\(address):\(port) · "
      case .https(let address, _): target = address.map { "\($0):443 · " } ?? ""
      case .ping(let address, let sequence, let size):
        target = "\(address) seq=\(sequence) size=\(size) · "
      case .route: target = ""
      }
      var probe = DiagnosticsProbe(
        stage: String(describing: observation.request.stage), domain: observation.request.domain,
        durationMs: Int(clamping: observation.durationMs), succeeded: observation.succeeded, detail: target + observation.detail,
        tlsDurationMs: observation.tlsDurationMs.map { Int(clamping: $0) })
      probe.id = "\(snapshot.sessionId):\(observation.request.id)"
      return probe
    }
    let prefix =
      snapshot.running
      ? "RUNNING"
      : snapshot.state == .passed
        ? "OK" : snapshot.state == .failed ? "PROBLEMS FOUND" : "INCOMPLETE"
    let routeDetails = snapshot.routeIssues + snapshot.routeUnavailable
    let summary =
      snapshot.cancelled
      ? "INCOMPLETE - diagnostics cancelled or tunnel session changed"
      : prefix + (routeDetails.isEmpty ? "" : " - " + routeDetails.joined(separator: "; "))
    var result = DiagnosticsResult(
      summary: summary,
      lines: probes.map {
        "[probe] \($0.stage) \($0.domain): \($0.detail) duration=\($0.durationMs)ms"
      }
        + (snapshot.routeIssues + snapshot.routeUnavailable).map { "[probe] route: \($0)" },
      domains: snapshot.domains,
      checks: snapshot.checks.map {
        DiagnosticsCheck(
          id: String(describing: $0.stage), passed: Int($0.passed),
          attempted: Int($0.attempted), state: state($0.state),
          durationMs: Int(clamping: $0.durationMs), sampleCount: Int($0.sampleCount))
      },
      durationMs: Int(clamping: snapshot.durationMs),
      activeCheck: snapshot.activeStage.map { String(describing: $0) }, probes: probes)
    result.engineState = state(snapshot.state)
    result.domainStates = Dictionary(
      uniqueKeysWithValues: snapshot.domainStates.map { ($0.domain, state($0.state)) })
    return result
  }
}

// MARK: - Presentation

/// Shared interpretation of provider results; each platform supplies its layout.
public enum DiagnosticsPresentation {
  public static let checkIDs = [
    "dns", "tcp", "https", "dns6", "tcp6", "https6", "application", "ping", "ping6",
  ]
  public static let pingCheckIDs = ["ping", "ping6"]
  public static let pingNote =
    "Ping is informational. ICMP may be filtered; no reply alone does not mean the VPN is broken. RTT averages replies only."

  public static func pingProbes(_ result: DiagnosticsResult?) -> [DiagnosticsProbe] {
    (result?.probes ?? []).filter { pingCheckIDs.contains($0.stage) }
  }

  public static func label(for id: String) -> String {
    [
      "dns": "Tunnel DNS · IPv4", "tcp": "Tunnel TCP · IPv4",
      "https": "Tunnel HTTPS · IPv4", "dns6": "Tunnel DNS · AAAA", "tcp6": "Tunnel TCP · IPv6",
      "https6": "Tunnel HTTPS · IPv6", "application": "Application access",
      "ping": "Ping · IPv4", "ping6": "Ping · IPv6",
    ][id] ?? id
  }

  public static func passed(_ result: DiagnosticsResult?) -> Bool {
    result?.engineState == .passed
  }

  public static func incomplete(_ result: DiagnosticsResult?) -> Bool {
    result?.engineState == .incomplete
  }

  public static func domainState(_ result: DiagnosticsResult, domain: String)
    -> DiagnosticsCheck.State
  {
    result.domainStates[domain] ?? .incomplete
  }

  public static func filteredLogs(_ text: String, source: String, search: String) -> String {
    text.components(separatedBy: "\n").filter {
      // Include Rust records in the tunnel filter; the shared source tag does
      // not distinguish app-process diagnostics from provider-process records.
      (source == "all" || $0.contains("[\(source)]") || (source == "ne" && $0.contains("[rust]")))
        && (search.isEmpty || $0.localizedCaseInsensitiveContains(search))
    }.joined(separator: "\n")
  }

  public static func connectionDuration(_ elapsed: TimeInterval) -> String {
    let seconds = max(0, Int(elapsed))
    return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
  }
}

extension DiagnosticErrorKind: Codable {
  private static var values: [Self] {
    [.timeout, .dns, .connect, .tls, .http, .permission, .unavailable, .invalidResponse]
  }
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let name = try container.decode(String.self)
    guard let value = Self.values.first(where: { String(describing: $0) == name }) else {
      throw DecodingError.dataCorruptedError(
        in: container, debugDescription: "unknown diagnostic error kind")
    }
    self = value
  }
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(String(describing: self))
  }
}
