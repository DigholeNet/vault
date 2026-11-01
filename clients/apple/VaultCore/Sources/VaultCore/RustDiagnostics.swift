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

// MARK: - Rust transport and engine

/// Runs Rust diagnostics and returns native snapshots without App presentation types.
public enum RustDiagnostics {
    /// All network execution is Rust-owned. Swift only forwards IPC and cancellation.
    public static func execute(
        _ request: AppleProbeRequest, tunnelAddress: String?,
        cancellation: DiagnosticsCancellation
    ) -> AppleProbeResponse {
        if request.tunnel && tunnelAddress == nil {
            return .failed(kind: .unavailable, detail: "current tunnel address unavailable")
        }
        do {
            let transport = try DiagnosticTransport(tunnelAddress: request.tunnel ? tunnelAddress : nil)
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
                timeoutMs: UInt64(max(0, min(6, request.timeout)) * 1000)
            )
            return AppleProbeResponse(response)
        } catch { return .failed(kind: .unavailable, detail: "\(error)") }
    }

    /// Drives the Rust engine; `execute` dispatches each request to Rust transport.
    /// Must be called on a worker queue. A missing IPC reply invalidates the run.
    public static func run(
        context: AppleDiagnosticContext, cancellation: DiagnosticsCancellation,
        execute: (DiagnosticRequest, UInt64) -> DiagnosticResponse?,
        onProgress: ((DiagnosticSnapshot) -> Void)? = nil
    ) throws -> DiagnosticSnapshot {
        let engine = try context.makeEngine()
        let token = cancellation.onCancel { try? engine.cancel() }
        defer { cancellation.removeHandler(token) }
        while !cancellation.isCancelled, let request = try engine.nextRequest() {
            onProgress?(engine.snapshot())
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
        return engine.snapshot()
    }
}
