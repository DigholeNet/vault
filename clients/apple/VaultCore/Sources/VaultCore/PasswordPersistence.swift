// SPDX-License-Identifier: MIT
import Foundation

/// Keeps the legacy recovery copy until the credential store confirms a save.
public struct PasswordPersistence {
    private let read: () throws -> String
    private let write: (String) throws -> Void
    private let readLegacy: () -> String?
    private let clearLegacy: () -> Void

    public init(
        read: @escaping () throws -> String,
        write: @escaping (String) throws -> Void,
        readLegacy: @escaping () -> String?,
        clearLegacy: @escaping () -> Void
    ) {
        self.read = read
        self.write = write
        self.readLegacy = readLegacy
        self.clearLegacy = clearLegacy
    }

    public func load() throws -> String {
        if let legacy = readLegacy(), !legacy.isEmpty {
            try write(legacy)
            clearLegacy()
            return legacy
        }
        return try read()
    }

    public func save(_ password: String) throws {
        try write(password)
        // A user may replace the password after an earlier failed migration.
        clearLegacy()
    }
}
