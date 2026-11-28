// SPDX-License-Identifier: MIT
import SwiftUI

struct ProfileServerLabel: View {
    let host: String
    let port: Int
    let milliseconds: UInt64?

    var body: some View {
        let address = Text(verbatim: "\(host):\(port)")
        let latency = latencyText
        Text("\(address) · \(latency)")
            .font(.system(size: 12, design: .monospaced))
            .foregroundStyle(VaultTheme.textSecondary)
    }

    private var latencyText: Text {
        guard let milliseconds else { return Text(verbatim: "--") }
        return Text(verbatim: "\(milliseconds.formatted()) ms").foregroundStyle(VaultTheme.primary)
    }
}
