// SPDX-License-Identifier: MIT
import SwiftUI
import VaultCore

struct ProfileServerLabel: View {
    let host: String
    let port: Int

    @State private var result: (host: String, milliseconds: UInt64?)?

    var body: some View {
        let address = Text(verbatim: "\(host):\(port)")
        let latency = latencyText
        Text("\(address) · \(latency)")
            .font(.system(size: 12, design: .monospaced))
            .foregroundStyle(VaultTheme.textSecondary)
            .task(id: host) {
                result = nil
                let milliseconds = await withCheckedContinuation { continuation in
                    DispatchQueue.global(qos: .utility).async { [host] in
                        continuation.resume(returning: probeHostLatencyMs(host: host))
                    }
                }
                guard !Task.isCancelled else { return }
                result = (host, milliseconds)
            }
    }

    private var latencyText: Text {
        guard let result, result.host == host else { return Text(verbatim: "--") }
        guard let milliseconds = result.milliseconds else {
            return Text(verbatim: "- ms").foregroundStyle(VaultTheme.danger)
        }
        return Text(verbatim: "\(milliseconds.formatted()) ms").foregroundStyle(VaultTheme.primary)
    }
}
