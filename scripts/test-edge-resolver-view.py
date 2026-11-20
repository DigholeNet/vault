#!/usr/bin/env python3
"""Verify Edge's resolver view under systemd without touching host DNS."""

from configparser import ConfigParser
from contextlib import ExitStack
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


SERVICE = Path(__file__).resolve().parents[1] / "clients/linux/assets/edge.service"


def mount_properties(fixture, resolver):
    config = ConfigParser(interpolation=None)
    config.read(SERVICE, encoding="utf-8")
    service = config["Service"]
    if "-/etc/resolv.conf" not in service["ReadWritePaths"].split():
        raise RuntimeError("edge.service is missing the resolver write exception")
    bind = service["BindReadOnlyPaths"].replace("/run/vault-resolver-view", str(fixture / "view"))
    bind = bind.replace("/etc:", f"{fixture / 'etc'}:", 1)
    return [
        f"--property=ProtectSystem={service['ProtectSystem']}",
        f"--property=ReadWritePaths=-{resolver} {fixture / 'sync'}",
        f"--property=BindReadOnlyPaths={bind}",
    ]


def verify(binary, kind):
    with ExitStack() as cleanup:
        fixture = Path(cleanup.enter_context(
            tempfile.TemporaryDirectory(prefix="edge-resolver-", dir="/var/lib")
        ))
        for name in ("etc", "sync", "view", "target"):
            (fixture / name).mkdir()
        test = fixture / "edge-test"
        shutil.copyfile(binary, test)
        test.chmod(0o755)
        selinuxenabled = shutil.which("selinuxenabled")
        if selinuxenabled and subprocess.run([selinuxenabled], check=False).returncode == 0:
            subprocess.run(["chcon", "--reference=/usr/bin/true", str(test)], check=True)
        resolver = fixture / "etc/resolv.conf"
        target = resolver if kind == "regular" else fixture / "target/resolv.conf"
        target.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
        if kind == "symlink":
            resolver.symlink_to(target)
        elif kind == "bind":
            resolver.write_text("nameserver 198.51.100.53\n", encoding="utf-8")
            subprocess.run(["mount", "--bind", str(target), str(resolver)], check=True)
            cleanup.callback(subprocess.run, ["umount", str(resolver)], check=True)
            (fixture / "sync/bound").touch()

        command = [
            "systemd-run", "--wait", "--collect",
            "--property=RuntimeMaxSec=20s",
            *mount_properties(fixture, resolver),
            f"--setenv=VAULT_RESOLVER_TEST_DIR={fixture}",
            str(test), "--exact", "dns::tests::resolver_view_systemd", "--ignored",
        ]
        if kind == "bind":
            subprocess.run(command, check=True, timeout=25)
            assert target.read_text(encoding="utf-8") == "nameserver 192.0.2.53\n"
            assert not (fixture / "sync/journal.json").exists()
            return

        with subprocess.Popen(command) as service:
            deadline = time.monotonic() + 10
            while not (fixture / "sync/ready").exists():
                if service.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("resolver test service did not become ready")
                time.sleep(0.02)
            assert target.read_text(encoding="utf-8") == "nameserver 1.1.1.1\n"
            replacement = target.with_name("replacement")
            replacement.write_text("nameserver 203.0.113.53\n", encoding="utf-8")
            if kind == "symlink":
                next_link = resolver.with_name("next")
                next_link.symlink_to(replacement)
                next_link.replace(resolver)
            else:
                replacement.replace(target)
            (fixture / "sync/replaced").touch()
            if service.wait(timeout=20):
                raise RuntimeError("resolver test service failed")

        subprocess.run(command, check=True, timeout=25)
        assert resolver.read_text(encoding="utf-8") == "nameserver 203.0.113.53\n"
        if kind == "symlink":
            assert target.read_text(encoding="utf-8") == "nameserver 192.0.2.53\n"
        assert not (fixture / "sync/journal.json").exists()


if __name__ == "__main__":
    executable = Path(sys.argv[1]).resolve(strict=True)
    for resolver_kind in ("regular", "symlink", "bind"):
        verify(executable, resolver_kind)
