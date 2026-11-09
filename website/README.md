# Vault website

Buildless bilingual website for GitHub Pages. HTML, CSS, JavaScript and local assets only; no browser dependencies, third-party fonts or trackers. Preview requires no build step. The Pages workflow refreshes release metadata and the local Android QR before uploading the site.

## Preview

From the repository root:

```sh
python3 -m http.server 8080 --directory website
```

Open http://localhost:8080. Language follows browser preferences on first visit; the language button saves the selection locally. Without JavaScript, Chinese content and navigation remain usable.

## Deploy

In the GitHub repository, select **Settings → Pages → Build and deployment → Source → GitHub Actions**. Push these files to `main`, or run the **GitHub Pages** workflow manually. The workflow deploys only `website/`, including its screenshots. Relative asset URLs support both project Pages and custom domains.

Expected project URL: https://digholenet.github.io/vault/ (available after successful deployment).

Edit text in paired `data-zh` / `data-en` attributes in `index.html`, keeping the default Chinese text in sync. Product claims reflect the repository README. The homepage reads `window.vaultRelease` to show the latest stable version and publication date; without a stable release it shows DEV / development status. This status updates with the download links and needs no manual release-time text change. Screenshots are copied from `docs/screenshots/`; replace the website copies when the apps change.

Brand and browser icons use an unchanged copy of `clients/apple/Vault/Assets.xcassets/AppIcon.appiconset/ios-1024.png` at `assets/app-icon.png`. Keep this copy in sync with the app.

Visual direction: bright white and soft blue surfaces with the app’s blue/purple branding. The architecture section follows app screenshots and documents native platforms, the shared bridge, Rust core, encrypted UDP transport and Linux server responsibilities.

The hero is a code-native conceptual illustration of encrypted transport, centered on the original app icon. It is not live connection status. The architecture diagram separately presents native platform lanes, the shared mobile bridge, direct Linux linking, Rust core modules and Linux server responsibilities. Real macOS/iOS/Android screenshots complete the introduction, before Architecture.

## Light and dark themes

Use the header’s sun/moon control to switch themes. First visits follow the OS setting; a manual choice is saved under `vault-theme`. System changes continue to apply until a manual choice is made. `theme.js` applies the theme before CSS loads to avoid a light flash. Preview a specific style at `/?theme=light` or `/?theme=dark` (also supported under the project Pages path). Screenshots retain their original application appearance.

## Content sources

Keep the site aligned with these repository sources:

- `README.md`, `CHANGELOG.md`: development status and release availability.
- `clients/apple/Vault.xcodeproj/project.pbxproj`, `clients/android/gradle/libs.versions.toml`: actual app OS requirements, distinct from shared-package requirements.
- `Cargo.toml`, component READMEs: build toolchain and deployment prerequisites.
- `core/src/client.rs`, `core/src/protocol.rs`, `SECURITY.md`: heartbeat/retry behavior, clock tolerance and shared-password trust.
- `supernode/src/network.rs`, `supernode/README.md`: host-wide forwarding and RA changes persist after shutdown.
- `PRIVACY.md`, `docs/diagnostics-engine.md`: handshake metadata, server operator visibility and diagnostic probe scopes.
- `docs/performance.md`: implementation timings are not throughput or recovery guarantees.

The FAQ uses native HTML `details` elements, works without JavaScript, and is available in both languages and themes. Security reports link to the private-reporting policy; ordinary bugs link to GitHub Issues.

## Downloads and onboarding

Downloads follows Architecture and precedes Get started. Five navigation destinations are tracked by scroll position: Architecture, Downloads, Get started, Developers and FAQ. Mobile navigation uses two rows.

- Android: the button and QR resolve to the same APK when a stable release contains one; otherwise both point to the release page, with an explicit fallback label.
- iOS: source builds only; no public Ad Hoc IPA is linked.
- macOS: the app ZIP from the latest stable release.
- Linux: separate amd64 and arm64 Debian packages for `edge` and `supernode`, with architecture-labelled download links.
- Get started: prepare a trusted server or self-host, configure a client, then connect and verify. Self-hosting prerequisites and the example configuration are in an optional native HTML disclosure.

`scripts/update-site-release.py` reads GitHub’s latest stable release, matches the actual asset naming in `.github/workflows/release.yml`, writes `website/release-data.js`, and generates `website/assets/android-release-qr.svg`. It requires `qrcode==8.2` (SVG only; no Pillow). No GitHub API or external QR service is called by visitors’ browsers. No release is a supported empty state; API/network errors fail the update rather than silently claiming no release. Missing assets fall back individually to the release page.

The Pages workflow refreshes the snapshot on website/script pushes, manual runs, release events, successful tag-push runs of the `Release` workflow, and daily. The `workflow_run` trigger covers automatic releases created with `GITHUB_TOKEN`, whose release events do not trigger another workflow. It accepts only successful `push` runs from this repository and skips failed or manual artifact-only release builds. Deployment checks out `main`, fetches the latest stable release from GitHub, and does not consume artifacts from the triggering run. Daily refresh remains a fallback for later release or asset changes. Regenerate the checked-in snapshot locally when needed:

```sh
python3 -m venv /tmp/vault-site-tools
/tmp/vault-site-tools/bin/pip install qrcode==8.2
/tmp/vault-site-tools/bin/python scripts/update-site-release.py
```

For a release-driven deployment, the upload uses a freshly generated snapshot; the workflow does not commit generated files back to the repository. If release asset names change, update the script’s patterns at the same time. Client screenshots retain their original app theme in both website themes.

The download layout uses two consistent platform cards per row on desktop and one per row on mobile. Android scanning has its own strip below the cards so the QR does not distort card alignment. Run `python3 -B scripts/test-site-release.py` to validate release/asset selection and error handling without network access or third-party packages.

Chapter responsibilities: the introduction shows real app interfaces and links to the full screenshot gallery. Downloads owns platform requirements, packages, the Android QR and source-build links. Get started explains preparing a server, configuring a client and verifying the connection. OS integrations remain in Architecture rather than being repeated in a platform table.

