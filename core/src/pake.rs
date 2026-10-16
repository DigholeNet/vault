// SPDX-License-Identifier: MIT
//! SPAKE2 password-authenticated key exchange.
//!
//! Replaces password-derived Ed25519 signatures for handshake
//! authentication. A passive observer of a SPAKE2 exchange cannot verify
//! password guesses offline (the handshake carries no password-derived
//! verifier), and an active attacker gets exactly one guess per protocol
//! run — which the supernode's per-IP handshake rate limit makes
//! impractical. Both sides finish with the same 32-byte key only when they
//! configured the same password; that key is mixed into the session-key
//! HKDF and keys the server's confirmation MAC.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

/// Fixed server identity for the PAKE exchange. The client identity is its
/// `PeerId`; the distinct role/identity pair binds the derived key to this
/// client–server pairing and prevents reflection between two clients.
pub const SERVER_IDENTITY: &[u8] = b"supernode";

/// SPAKE2 protocol state, consumed by [`PakeState::finish`].
pub struct PakeState(Spake2<Ed25519Group>);

/// Start the client side (role A). Returns the state and the 33-byte
/// message to embed in the handshake request.
pub fn start_client(password: &[u8], client_id: &[u8]) -> (PakeState, Vec<u8>) {
    let (state, message) = Spake2::<Ed25519Group>::start_a(
        &Password::new(password),
        &Identity::new(client_id),
        &Identity::new(SERVER_IDENTITY),
    );
    (PakeState(state), message)
}

/// Start the server side (role B). Returns the state and the 33-byte
/// message to embed in the handshake response.
pub fn start_server(password: &[u8], client_id: &[u8]) -> (PakeState, Vec<u8>) {
    let (state, message) = Spake2::<Ed25519Group>::start_b(
        &Password::new(password),
        &Identity::new(client_id),
        &Identity::new(SERVER_IDENTITY),
    );
    (PakeState(state), message)
}

impl PakeState {
    /// Complete the exchange with the peer's message. Succeeds even on a
    /// password mismatch (both sides then derive different keys); the
    /// mismatch is detected through the confirmation MAC or the first
    /// encrypted packet. The returned key material is zeroed on drop.
    pub fn finish(self, peer_message: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.0
            .finish(peer_message)
            .map(Zeroizing::new)
            .map_err(|e| anyhow::anyhow!("PAKE exchange failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_derives_same_key() {
        let id = b"0123456789abcdef";
        let (client_state, msg_a) = start_client(b"correct horse", id);
        let (server_state, msg_b) = start_server(b"correct horse", id);
        let key_client = client_state.finish(&msg_b).unwrap();
        let key_server = server_state.finish(&msg_a).unwrap();
        assert_eq!(&*key_client, &*key_server);
        assert_eq!(key_client.len(), 32);
    }

    #[test]
    fn wrong_password_derives_different_keys() {
        let id = b"0123456789abcdef";
        let (client_state, msg_a) = start_client(b"correct horse", id);
        let (server_state, msg_b) = start_server(b"wrong password", id);
        let key_client = client_state.finish(&msg_b).unwrap();
        let key_server = server_state.finish(&msg_a).unwrap();
        assert_ne!(&*key_client, &*key_server);
    }

    #[test]
    fn mismatched_identities_derive_different_keys() {
        let (client_state, msg_a) = start_client(b"pw", b"client-1");
        let (server_state, msg_b) = start_server(b"pw", b"client-2");
        let key_client = client_state.finish(&msg_b).unwrap();
        let key_server = server_state.finish(&msg_a).unwrap();
        assert_ne!(&*key_client, &*key_server);
    }

    #[test]
    fn truncated_message_is_rejected() {
        let id = b"0123456789abcdef";
        let (client_state, msg_a) = start_client(b"pw", id);
        let (server_state, msg_b) = start_server(b"pw", id);
        assert!(client_state.finish(&msg_b[..16]).is_err());
        assert!(server_state.finish(&msg_a).is_ok());
    }
}
