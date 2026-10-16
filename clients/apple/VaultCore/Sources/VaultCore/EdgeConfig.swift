//
//  EdgeConfig.swift
//  VaultCore
//
//

public struct EdgeConfig {
    var password: String
    var host: String
    var port: UInt16

    public init(password: String, host: String, port: UInt16) {
        self.password = password
        self.host = host
        self.port = port
    }
}
