# Contributing to Vault

Thank you for your interest in contributing to Vault! We welcome contributions from the
community.

## Code of Conduct

This project and everyone participating in it is governed by our commitment to:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive criticism
- Prioritize user privacy and security

## How to Contribute

### Reporting Bugs

Before creating a bug report, please:

1. Check if the issue already exists in
   the [issue tracker](https://github.com/DigholeNet/vault/issues)
2. Update to the latest version to see if the bug is already fixed
3. Collect relevant information: platform, OS version, vault version

When reporting bugs, include:

- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (redact passwords and other secrets)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear, descriptive title
- Provide detailed description of the proposed feature
- Explain why this enhancement would be useful
- Consider potential security implications

### Pull Requests

1. Fork the repository
2. Create a branch from `main` (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and ensure code compiles
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

#### Pull Request Guidelines

- Follow the existing code style (see Coding Standards below)
- Update documentation for any changed functionality
- Ensure your code compiles without warnings
- Keep changes focused and atomic
- Reference any related issues
- Commit messages in the conventional style (`feat:`, `fix:`, ...) are appreciated

## Development Setup

### Prerequisites

- Rust (stable; `rust-toolchain.toml` pins the channel)
- `protoc` (required by the protobuf build script in `core/`)
- For the Android client: Android SDK + NDK and `cargo-ndk`
- For the Apple client: full Xcode and the Rust Apple targets

### Building

See the [developer quick start](README.md#for-developers--build-from-source)
for clone-to-build commands per platform, and the component READMEs under
`clients/` and `supernode/` for details.

```bash
# Run the Rust test suites
cargo test -p vault-core --features test
cargo test -p supernode
```

## Coding Standards

### Rust

The protocol core, server, Linux client, and mobile bridge are all Rust:

- Run `cargo fmt` before committing
- Keep `cargo clippy` clean; fix or explicitly allow new lints
- Use `anyhow` for error handling
- Prefer safe code; every `unsafe` block needs a `// SAFETY:` justification comment

### Kotlin / Swift

Client apps follow the conventions of their platform:

- Kotlin: [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Swift: the project lints with SwiftLint (`swiftlint lint` in `clients/apple`)

## Testing

- Rust unit tests live next to the code (`#[cfg(test)]` modules); integration tests are in
  `core/tests/` and run against a mock server
- Protocol changes must keep client and server compatible — the wire protocol is versioned
  by the deployed supernodes, so treat protocol compatibility as frozen unless you are
  deliberately rolling a protocol upgrade
- Test on real devices/networks when possible (mobile data switching, backgrounding, NAT)

### Fuzzing

The `fuzz/` crate (cargo-fuzz, excluded from the main workspace) fuzzes the
network-facing parsers: handshake decoding, AEAD decrypt of arbitrary ciphertext,
and TUN frame parsing. It requires nightly Rust and cargo-fuzz:

```bash
cargo install cargo-fuzz
cd fuzz && cargo +nightly fuzz run fuzz_handshake   # or fuzz_decrypt / fuzz_tun_parse
```

Fuzz targets are not part of CI; run them locally when changing the parsing or
decryption code paths.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
