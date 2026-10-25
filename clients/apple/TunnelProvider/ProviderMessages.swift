// SPDX-License-Identifier: MIT
import Foundation
import VaultCore
import os.log

/// Decode and trace one OS provider request; preserve the legacy empty status request.
struct ProviderMessage {
    let command: ProviderCommandEnvelope?
    private let completion: ((Data?) -> Void)?
    private let received = ProcessInfo.processInfo.systemUptime
    private let prefix: String

    init(data: Data, session: String, completion: ((Data?) -> Void)?) {
        command = try? JSONDecoder().decode(ProviderCommandEnvelope.self, from: data)
        self.completion = completion
        prefix = "[session:\(session)] [request:\(command?.requestID ?? "legacy")] "
            + "command=\(command?.command ?? "status") providerPID=\(ProcessInfo.processInfo.processIdentifier)"
    }

    func trace(_ state: String, force: Bool) {
        if command?.trace == true || force { Logger.network.noticeAndFile("\(prefix) received \(state)") }
    }

    func reply(_ data: Data?) {
        if command?.trace == true {
            let elapsed = Int((ProcessInfo.processInfo.systemUptime - received) * 1000)
            Logger.network.noticeAndFile("\(prefix) reply bytes=\(data?.count ?? 0) durationMs=\(elapsed)")
        }
        completion?(data)
    }
}

extension PacketTunnelProvider {
    func handleMessage(_ message: ProviderMessage) {
        switch message.command?.command {
        case nil, "status":
            message.reply(try? JSONEncoder().encode(providerStatus))
        case "clearLogs":
            guard let token = message.command?.token, !token.isEmpty else { message.reply(Data([0])); return }
            do {
                try clearLogsIfNeeded(token)
                message.reply(Data([1]))
            } catch { message.reply(Data([0])) }
        case "startupStatus":
            message.reply(Data([providerStarted ? 1 : 0]))
        case "diagnosticContext":
            message.reply(diagnosticContext().flatMap { try? JSONEncoder().encode($0) })
        case "diagnosticProbe":
            guard let payload = message.command?.payload,
                let request = try? JSONDecoder().decode(AppleProbeRequest.self, from: payload)
                else { message.reply(nil); return }
            diagnostics.run(request, context: { [weak self] in self?.diagnosticContext() }, completionHandler: message.reply)
        case "cancelDiagnostics":
            if let token = message.command?.token { diagnostics.cancel(run: token) }
            message.reply(Data())
        case "logs":
            DispatchQueue.global(qos: .utility).async {
                let log = FileLogger.shared.readLog() ?? ""
                message.reply(String(log.suffix(512 * 1024)).data(using: .utf8))
            }
        default:
            message.reply(nil)
        }
    }
}
