// SPDX-License-Identifier: MIT
import Testing
@testable import VaultCore

private enum StorageFailure: Error { case unavailable }

@Test func migrationFailurePreservesLegacyPassword() {
    var legacy: String? = "recovery"
    let store = PasswordPersistence(
        read: { "stale" },
        write: { _ in throw StorageFailure.unavailable },
        readLegacy: { legacy },
        clearLegacy: { legacy = nil }
    )
    #expect(throws: StorageFailure.self) { try store.load() }
    #expect(legacy == "recovery")
}

@Test func successfulMigrationClearsLegacyOnlyAfterSave() throws {
    var legacy: String? = "recovery"
    var saved = ""
    let store = PasswordPersistence(
        read: { saved },
        write: { saved = $0 },
        readLegacy: { legacy },
        clearLegacy: {
            #expect(saved == "recovery")
            legacy = nil
        }
    )
    #expect(try store.load() == "recovery")
    #expect(legacy == nil)
}

@Test func failedUpdateCanBeRetriedWithoutDiscardingRecovery() throws {
    var legacy: String? = "recovery"
    var saved = "old"
    var unavailable = true
    let store = PasswordPersistence(
        read: { saved },
        write: {
            if unavailable { throw StorageFailure.unavailable }
            saved = $0
        },
        readLegacy: { legacy },
        clearLegacy: { legacy = nil }
    )
    #expect(throws: StorageFailure.self) { try store.save("new") }
    #expect(saved == "old")
    #expect(legacy == "recovery")
    unavailable = false
    try store.save("new")
    #expect(saved == "new")
    #expect(legacy == nil)
}

@Test func readFailuresAreReported() {
    let store = PasswordPersistence(
        read: { throw StorageFailure.unavailable },
        write: { _ in },
        readLegacy: { nil },
        clearLegacy: {}
    )
    #expect(throws: StorageFailure.self) { try store.load() }
}
