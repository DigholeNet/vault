#!/usr/bin/env python3
"""Release-link selection tests; no network or QR dependencies required."""
import importlib.util
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("site_release", Path(__file__).with_name("update-site-release.py"))
site_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site_release)
BASE = site_release.BASE


def release(names=()):
    return {
        "tag_name": "v0.1.0",
        "html_url": f"{BASE}/releases/tag/v0.1.0",
        "published_at": "2026-11-01T00:00:00Z",
        "assets": [{"name": name, "browser_download_url": f"{BASE}/releases/download/v0.1.0/{name}"} for name in names],
    }


class ReleaseSnapshotTests(unittest.TestCase):
    def test_empty_or_unstable_releases_do_not_offer_downloads(self):
        for data in [None, {"draft": True}, {"prerelease": True}]:
            state = site_release.release_snapshot(data)
            self.assertIsNone(state["version"])
            self.assertEqual(state["assets"], {})
            self.assertEqual(state["url"], f"{BASE}/releases")

    def test_actual_release_asset_names_match_publishing_workflow(self):
        data = release(["vault-android-v0.1.0.apk", "Vault-macOS-v0.1.0.zip", "edge-v0.1.0-amd64.deb", "edge-v0.1.0-arm64.deb", "supernode-v0.1.0-amd64.deb", "supernode-v0.1.0-arm64.deb", "Vault-iOS.ipa"])
        state = site_release.release_snapshot(data)
        self.assertEqual(set(state["assets"]), {"android", "macos", "edge-amd64", "edge-arm64", "supernode-amd64", "supernode-arm64"})
        self.assertEqual(state["version"], "v0.1.0")
        self.assertEqual(state["published"], "2026-11-01")

    def test_missing_platform_is_not_given_an_invented_url(self):
        state = site_release.release_snapshot(release(["vault-android-v0.1.0.apk"]))
        self.assertEqual(set(state["assets"]), {"android"})

    def test_unexpected_download_host_is_rejected(self):
        data = release(["vault-android-v0.1.0.apk"])
        data["assets"][0]["browser_download_url"] = "https://example.invalid/package.apk"
        with self.assertRaises(ValueError):
            site_release.release_snapshot(data)

    def test_duplicate_platform_assets_are_not_silently_selected(self):
        with self.assertRaises(ValueError):
            site_release.release_snapshot(release(["vault-android-v0.1.0.apk", "vault-android-v0.1.1.apk"]))

    def test_missing_latest_verifies_repository_access_before_empty_state(self):
        missing = HTTPError("https://api.github.com", 404, "not found", {}, None)
        with patch.object(site_release, "request_json", side_effect=[missing, []]) as request, patch.object(site_release, "write_snapshot") as write:
            site_release.main()
            self.assertEqual(request.call_args_list[1].args[0], "releases?per_page=1")
            self.assertIsNone(write.call_args.args[0]["version"])

    def test_api_failures_preserve_existing_snapshot(self):
        failure = HTTPError("https://api.github.com", 403, "rate limit", {}, None)
        with patch.object(site_release, "request_json", side_effect=failure), patch.object(site_release, "write_snapshot") as write:
            with self.assertRaises(HTTPError):
                site_release.main()
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
