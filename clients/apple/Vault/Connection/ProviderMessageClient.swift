// SPDX-License-Identifier: MIT
import NetworkExtension
import os.log
import VaultCore

final class ProviderMessageClient {
    struct Context {
        let operation: ProviderOperation
        let status: VpnStatus
        let terminating: Bool
    }

    private let context: () -> Context
    private let canSend: (ProviderCommand, NETunnelProviderManager) -> Bool
    private let deliver: (Data, NETunnelProviderManager, @escaping (Data?) -> Void) throws -> Void
    var lastMessageTrace: [ProviderCommand: (signature: String, time: TimeInterval)] = [:]

    init(
        context: @escaping () -> Context,
        canSend: @escaping (ProviderCommand, NETunnelProviderManager) -> Bool,
        deliver: @escaping (Data, NETunnelProviderManager, @escaping (Data?) -> Void) throws -> Void
    ) {
        self.context = context
        self.canSend = canSend
        self.deliver = deliver
    }

    /// The reply always arrives asynchronously on main; nil means the channel failed.
    func send(
        _ request: ProviderCommandEnvelope,
        manager: NETunnelProviderManager?,
        timeout: TimeInterval = 8,
        completion: @escaping (Data?) -> Void
    ) {
        if !Thread.isMainThread {
            DispatchQueue.main.async {
                self.send(request, manager: manager, timeout: timeout, completion: completion)
            }
            return
        }
        let command = request.command
        let requestID = String(UUID().uuidString.prefix(8))
        let requested = ProcessInfo.processInfo.systemUptime
        let operation = context().operation.id
        let appPID = ProcessInfo.processInfo.processIdentifier
        let prefix = "[request:\(requestID)] [operation:\(operation)] command=\(command.rawValue) appPID=\(appPID)"
        let replyLock = NSLock()
        var replied = false
        var tracing = false
        var sendContext = "managerLookup=pending"

        func reply(_ data: Data?, reason: String = "response") {
            replyLock.lock()
            let first = !replied
            if first { replied = true }
            let emit = tracing || reason != "response" || data == nil
            let context = sendContext
            replyLock.unlock()
            if emit {
                let elapsed = Int((ProcessInfo.processInfo.systemUptime - requested) * 1000)
                Logger.network.noticeAndFile(
                    "\(prefix) reply reason=\(reason) first=\(first) bytes=\(data?.count ?? 0) durationMs=\(elapsed) \(context)"
                )
            }
            if first { DispatchQueue.main.async { completion(data) } }
        }

        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            replyLock.lock()
            let pending = !replied
            replyLock.unlock()
            if pending { reply(nil, reason: "timeout") }
        }

        guard let manager else {
            // Offline readers use cached data instead of waking an idle extension.
            reply(nil, reason: "noActiveManager")
            return
        }
        let snapshot = context()
        let status = manager.connection.status
        let contextDescription = """
        neStatus=\(status.rawValue) uiStatus=\(snapshot.status) preparing=\(snapshot.operation.preparing) \
        stopping=\(snapshot.operation.stopping) terminating=\(snapshot.terminating) onDemand=\(manager.isOnDemandEnabled)
        """
        let emit = shouldTrace(
            command, context: contextDescription, manager: manager, snapshot: snapshot
        )
        replyLock.lock()
        tracing = emit
        sendContext = contextDescription
        let expired = replied
        replyLock.unlock()
        guard !expired else {
            Logger.network.noticeAndFile("\(prefix) skipped reason=requestExpired \(contextDescription)")
            return
        }
        // Sending to an inactive provider can allocate a utun for IdleIPC.
        guard canSend(command, manager) else {
            Logger.network.noticeAndFile("\(prefix) skipped reason=providerNotActive \(contextDescription)")
            reply(nil, reason: "providerNotActive")
            return
        }
        if emit {
            Logger.network.noticeAndFile(
                "\(prefix) send \(contextDescription) interfaces=\(FileLogger.tunnelInterfaceSummary())"
            )
        }
        do {
            let message = try request.encoded(requestID: requestID, trace: emit)
            try deliver(message, manager) { data in reply(data) }
        } catch {
            Logger.network.errorAndFile("\(prefix) send failed error=\(error.localizedDescription)")
            reply(nil, reason: "sendError")
        }
    }

    private func shouldTrace(
        _ command: ProviderCommand,
        context: String,
        manager: NETunnelProviderManager,
        snapshot: Context
    ) -> Bool {
        let status = manager.connection.status
        let now = ProcessInfo.processInfo.systemUptime
        let periodic = [ProviderCommand.status, .logs, .diagnosticProbe, .startupStatus].contains(command)
        let routinePolling = command == .status || command == .logs
        let signature = "\(ObjectIdentifier(manager.connection))|\(context)"
        let last = lastMessageTrace[command]
        let emit = !periodic || snapshot.terminating
            || status == .disconnected || status == .invalid || status == .disconnecting
            || last?.signature != signature || (!routinePolling && now - (last?.time ?? 0) >= 30)
        if emit { lastMessageTrace[command] = (signature, now) }
        return emit
    }
}

extension VpnManager {
    /// Send a provider-message command and return the raw reply. The reply
    /// always arrives asynchronously on main; nil means the message channel itself
    /// failed (no manager, not a provider session, no response).
    func sendProviderCommand(
        _ request: ProviderCommandEnvelope,
        timeout: TimeInterval = 8,
        completion: @escaping (Data?) -> Void
    ) {
        if !Thread.isMainThread {
            DispatchQueue.main.async {
                self.sendProviderCommand(request, timeout: timeout, completion: completion)
            }
            return
        }
        providerMessages.send(
            request,
            manager: activeVPN,
            timeout: timeout,
            completion: completion
        )
    }
}
