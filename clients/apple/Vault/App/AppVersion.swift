// SPDX-License-Identifier: MIT
import Foundation

extension Bundle {
    var appVersionShort: String {
        infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    var appVersion: String {
        let version = appVersionShort
        let build = infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(version).\(build)"
    }
}
