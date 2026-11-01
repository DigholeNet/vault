// SPDX-License-Identifier: MIT
import NetworkExtension
import os.log
import VaultCore

extension VpnManager {
    /// Send a provider-message command and return the raw reply. The reply
    /// always arrives asynchronously on main; nil means the message channel itself
    /// failed (no manager, not a provider session, no response).
    func sendProviderCommand(_ request: ProviderCommandEnvelope, timeout: TimeInterval = 8, completion: @escaping (Data?) -> Void) {
        if !Thread.isMainThread {
            DispatchQueue.main.async { self.sendProviderCommand(request, timeout: timeout, completion: completion) }
            return
        }
        let command = request.command
        let requestID = String(UUID().uuidString.prefix(8))
        let requested = ProcessInfo.processInfo.systemUptime
        let operation = providerOperation.id
        let appPID = ProcessInfo.processInfo.processIdentifier
        let prefix = "[request:\(requestID)] [operation:\(operation)] command=\(command.rawValue) appPID=\(appPID)"
        let replyLock = NSLock()
        var replied = false
        // Reply callbacks may arrive off-main. The trace decision shares the
        // reply lock so timeout and send races cannot misreport a response.
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
                Logger.network
                    .noticeAndFile(
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
        let send: (NETunnelProviderManager) -> Void = { manager in
            let status = manager.connection.status
            let now = ProcessInfo.processInfo.systemUptime
            let context = """
            neStatus=\(status.rawValue) uiStatus=\(self.vpnStatus) preparing=\(self.providerOperation.preparing) \
            stopping=\(self.providerOperation.stopping) terminating=\(self.terminationInProgress) onDemand=\(manager.isOnDemandEnabled)
            """
            let periodic = [ProviderCommand.status, .logs, .diagnosticProbe, .startupStatus].contains(command)
            let signature = "\(ObjectIdentifier(manager.connection))|\(context)"
            let last = self.lastMessageTrace[command]
            let emit = !periodic || self.terminationInProgress
                || status == .disconnected || status == .invalid || status == .disconnecting
                || last?.signature != signature || now - (last?.time ?? 0) >= 30
            if emit { self.lastMessageTrace[command] = (signature, now) }
            replyLock.lock()
            tracing = emit
            sendContext = context
            let expired = replied
            replyLock.unlock()
            guard !expired else {
                Logger.network.noticeAndFile("\(prefix) skipped reason=requestExpired \(context)")
                return
            }
            // This is the final gate immediately before the OS message API.
            // Sending to an inactive provider can allocate a utun for IdleIPC.
            guard self.canSendProviderCommand(command, manager: manager) else {
                Logger.network.noticeAndFile("\(prefix) skipped reason=providerNotActive \(context)")
                reply(nil, reason: "providerNotActive")
                return
            }
            if emit {
                Logger.network.noticeAndFile("\(prefix) send \(context) interfaces=\(FileLogger.tunnelInterfaceSummary())")
            }
            do {
                let message = try request.encoded(requestID: requestID, trace: emit)
                try self.deliverProviderMessage(message, manager: manager) { data in reply(data) }
            } catch {
                Logger.network.errorAndFile("\(prefix) send failed error=\(error.localizedDescription)")
                reply(nil, reason: "sendError")
            }
        }
        if let manager = self.activeVPN { send(manager) }
        else {
            // Loading a saved profile solely to send a message can wake an
            // otherwise idle extension. Offline readers must use cached data.
            reply(nil, reason: "noActiveManager")
        }
    }
}
