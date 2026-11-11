// SPDX-License-Identifier: MIT
import NetworkExtension
import os.log
import VaultCore

final class ProviderStatusPoller {
    private var timer: Timer?
    private var generation: UInt64 = 0
    private var queryInFlight = false
    private var lastQueryFailure: String?

    private let activeConnection: () -> NEVPNConnection?
    private let sessionGeneration: () -> UInt64
    private let send: (ProviderCommandEnvelope, TimeInterval, @escaping (Data?) -> Void) -> Void
    private let apply: (ProviderStatus) -> Void
    private let reset: () -> Void

    init(
        activeConnection: @escaping () -> NEVPNConnection?,
        sessionGeneration: @escaping () -> UInt64,
        send: @escaping (ProviderCommandEnvelope, TimeInterval, @escaping (Data?) -> Void) -> Void,
        apply: @escaping (ProviderStatus) -> Void,
        reset: @escaping () -> Void
    ) {
        self.activeConnection = activeConnection
        self.sessionGeneration = sessionGeneration
        self.send = send
        self.apply = apply
        self.reset = reset
    }

    deinit {
        timer?.invalidate()
    }

    func start() {
        guard timer == nil else { return }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func stop() {
        generation &+= 1
        timer?.invalidate()
        timer = nil
        queryInFlight = false
        reset()
    }

    private func refresh() {
        guard !queryInFlight else { return }
        queryInFlight = true
        let generation = generation
        queryProviderStatus { [weak self] status in
            guard let self, self.generation == generation else { return }
            self.queryInFlight = false
            if let status { self.apply(status) }
        }
    }

    /// The provider owns live addresses and counters on both platforms.
    private func queryProviderStatus(completion: @escaping (ProviderStatus?) -> Void) {
        guard let connection = activeConnection() else {
            completion(nil)
            return
        }
        let generation = sessionGeneration()
        send(.init(.status), 3) { data in
            guard self.sessionGeneration() == generation,
                  self.activeConnection() === connection,
                  connection.status == .connected || connection.status == .reasserting else {
                completion(nil)
                return
            }
            guard let data, let status = try? JSONDecoder().decode(ProviderStatus.self, from: data) else {
                self.reportQueryFailure("provider status unavailable or invalid")
                completion(nil)
                return
            }
            self.reportQueryFailure(nil)
            completion(status)
        }
    }

    /// Log only on state change; the query runs once per second.
    private func reportQueryFailure(_ reason: String?) {
        guard reason != lastQueryFailure else { return }
        lastQueryFailure = reason
        if let reason {
            Logger.network.errorAndFile("Provider status query failed: \(reason)")
        } else {
            Logger.network.noticeAndFile("Provider status query succeeded")
        }
    }
}
