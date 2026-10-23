//
//  Edge.swift
//  VaultCore
//
//
//  Thin Swift glue over the Rust vault-core client session (via UniFFI).
//  All protocol logic (handshake, heartbeat, reconnect, encryption, data
//  pump) lives in vault-core; this class only adapts it to the Network
//  Extension callbacks. Mirrors Edge.kt on Android.
//
import Foundation
import os.log

public enum EdgeError: Error {
    case connectionFailed
    case applyIpFailed
    case settingIpFailed
    case invalidChannelState
}

/// Core VPN networking component managing the connection to the supernode.
public final class Edge: @unchecked Sendable {

    // The bridge currently delivers errors as Display strings. Match Darwin
    // errno suffixes, not localized descriptions; timeouts remain retryable.
    static func isNetworkUnreachable(_ error: String) -> Bool {
        guard error.hasPrefix("IO error:") else { return false }
        return [ENETDOWN, ENETUNREACH, EHOSTDOWN, EHOSTUNREACH].contains {
            error.hasSuffix("(os error \($0))")
        }
    }

    /// "Handshake failed: ..." from the bridge's VpnError::HandshakeFailed
    /// Display. The core races every candidate before reporting, so this
    /// means all addresses failed; the provider fails the start (with
    /// backoff) instead of waiting for the backstop timeout.
    static func isHandshakeFailure(_ error: String) -> Bool {
        error.hasPrefix("Handshake failed:")
    }

    /// Adapts the UniFFI `EdgeCallbacks` to the closures passed to `Edge.init`.
    /// Callbacks fire on Rust worker threads; the handlers here only forward.
    private final class Callbacks: EdgeCallbacks, @unchecked Sendable {
        let onData: (Data) -> Void
        let onIpAssigned: (String, String, String, Int32) -> Void
        let onNetworkUnreachable: () -> Void
        let onHandshakeFailed: () -> Void

        init(
            onData: @escaping (Data) -> Void,
            onIpAssigned: @escaping (String, String, String, Int32) -> Void,
            onNetworkUnreachable: @escaping () -> Void,
            onHandshakeFailed: @escaping () -> Void
        ) {
            self.onData = onData
            self.onIpAssigned = onIpAssigned
            self.onNetworkUnreachable = onNetworkUnreachable
            self.onHandshakeFailed = onHandshakeFailed
        }

        func onDataBatch(packets: [Data]) {
            // Runs on a Rust worker thread where no autoreleasepool exists;
            // without one, bridged Objective-C objects accumulate for the
            // whole session and the extension gets jetsam-killed under load.
            autoreleasepool {
                for packet in packets {
                    self.onData(packet)
                }
            }
        }

        func onIpAssigned(ipv4: String, ipv4Mask: String, ipv6: String, ipv6Prefixlen: Int32) {
            autoreleasepool {
                self.onIpAssigned(ipv4, ipv4Mask, ipv6, ipv6Prefixlen)
            }
        }

        func onError(error: String) {
            Logger.network.errorAndFile("vault-core client error: \(error)")
            if Edge.isNetworkUnreachable(error) {
                onNetworkUnreachable()
            } else if Edge.isHandshakeFailure(error) {
                onHandshakeFailed()
            }
        }

        func protectSocket(fd: Int32) -> Bool {
            // Not needed on Apple platforms: traffic from the Network
            // Extension process bypasses the tunnel by default.
            true
        }
    }

    private let rustEdge: RustEdge
    /// Retained so the UniFFI callback handle stays valid for the lifetime
    /// of the Rust object.
    private let callbacks: Callbacks

    public init(
        config: EdgeConfig,
        id: Data,
        hosts: [String],
        deviceName: String,
        platform: String,
        onData: @escaping ((Data) -> Void),
        onIpAssigned: @escaping ((String, String, String, Int32) -> Void),
        pendingCompletion: @escaping ((Error?) -> Void),
        onNetworkUnreachable: @escaping () -> Void = {},
        onHandshakeFailed: @escaping () -> Void = {}
    ) throws {
        // `pendingCompletion` is accepted for API compatibility with the
        // previous Swift implementation. It is intentionally not invoked
        // here: the tunnel provider owns the startTunnel completion handler
        // and finishes it via its own timeout/backoff logic.
        _ = pendingCompletion

        let callbacks = Callbacks(onData: onData, onIpAssigned: onIpAssigned,
                                  onNetworkUnreachable: onNetworkUnreachable,
                                  onHandshakeFailed: onHandshakeFailed)
        self.callbacks = callbacks
        // The Rust core races every candidate Happy-Eyeballs style (300 ms
        // stagger, first completed handshake wins).
        self.rustEdge = try RustEdge(
            password: config.password,
            hosts: hosts,
            port: Int32(config.port),
            id: id,
            deviceName: deviceName,
            platform: platform,
            callbacks: callbacks
        )
        // Starts the connection loop (handshake, heartbeat, reconnect) in
        // the background; IP assignment arrives via onIpAssigned.
        try self.rustEdge.connect()
        Logger.network.noticeAndFile("Edge (vault-core) connecting to \(hosts)")
    }

    /// Queues an IP packet for the tunnel. Throws when not connected;
    /// drops during reconnect are expected (UDP semantics).
    public func writeData(data: Data) throws {
        do {
            try self.rustEdge.writeData(data: data)
        } catch let error as VpnError {
            if case .NotConnected = error {
                throw EdgeError.invalidChannelState
            }
            throw error
        }
    }

    /// Rebuild the UDP connection without replacing the tunnel or statistics.
    public func reconnect() throws {
        try rustEdge.reconnect()
    }

    /// Shuts down the session. Safe to call multiple times.
    public func close() throws {
        Logger.network.noticeAndFile("Edge close requested")
        try self.rustEdge.shutdown()
    }

    /// Current traffic statistics computed by the Rust core.
    public func getTrafficStats() -> TrafficStats {
        self.rustEdge.getTrafficStats()
    }

    /// Seconds since the last authenticated packet from the server.
    public func getLastActivityAgeSecs() -> UInt64 {
        self.rustEdge.getLastActivityAgeSecs()
    }

    deinit {
        try? self.rustEdge.shutdown()
    }
}
