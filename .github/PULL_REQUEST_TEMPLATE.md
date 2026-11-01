## Summary

<!-- What does this PR change and why? Link related issues. -->

## Platform(s) affected

- [ ] Android
- [ ] iOS / macOS
- [ ] Linux client (edge)
- [ ] Supernode

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --locked --workspace --all-targets --features vault-core/test -- -D warnings` passes
- [ ] Tests added/updated where applicable; `cargo test --locked --workspace --features vault-core/test` passes
- [ ] Protocol changes preserve compatibility within the wire version; breaking changes increment `PROTOCOL_VERSION`, update protocol docs/changelog, and require coordinated client/server upgrades
- [ ] Docs updated (README / protocol docs / manpages) when behavior or layout changed
