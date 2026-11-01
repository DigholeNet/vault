// SPDX-License-Identifier: MIT
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use tokio::net::UnixDatagram;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

pub struct SysSignal {
    sock_path: String,
    quit: Arc<AtomicBool>,
    socket_identity: Option<(u64, u64)>,
    // Bound up front (before privilege dropping makes /run unwritable);
    // taken and converted to a tokio socket by init().
    socket: Mutex<Option<std::os::unix::net::UnixDatagram>>,
    // Keep the same lock-file inode across restarts. Unlinking it would let
    // another process lock a different inode while the first is still held.
    _instance_lock: Option<File>,
}

impl SysSignal {
    /// Sender-side handle (e.g. `-s quit`): holds only the path and must
    /// never bind — binding would unlink the running instance's socket.
    pub fn new(sock_path: String) -> Self {
        Self {
            sock_path,
            quit: Arc::new(AtomicBool::new(false)),
            socket: Mutex::new(None),
            _instance_lock: None,
            socket_identity: None,
        }
    }

    /// Acquire exclusive ownership before inspecting or removing a stale
    /// socket. The lock and std socket can safely be inherited by daemonize.
    pub fn bind(sock_path: String) -> anyhow::Result<Self> {
        let path = Path::new(&sock_path);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(format!("{sock_path}.lock"))
            .context("open instance lock")?;
        lock.try_lock()
            .map_err(|error| anyhow::anyhow!("another instance owns {sock_path}: {error}"))?;

        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket(),
                    "control path is not a socket: {sock_path}"
                );
                // Also protect an older daemon that does not hold our lock.
                let probe = std::os::unix::net::UnixDatagram::unbound()?;
                match probe.connect(path) {
                    Ok(()) => anyhow::bail!("another instance is listening on {sock_path}"),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("check existing control socket"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect control socket"),
        }
        let socket = std::os::unix::net::UnixDatagram::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let signal = Self {
            sock_path: sock_path.clone(),
            quit: Arc::new(AtomicBool::new(false)),
            socket: Mutex::new(Some(socket)),
            _instance_lock: Some(lock),
            socket_identity: Some((metadata.dev(), metadata.ino())),
        };
        // Errors after construction drop the guard and remove our socket.
        signal
            .socket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .expect("socket just bound")
            .set_nonblocking(true)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(signal)
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        let socket = self
            .socket
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| anyhow::anyhow!("control socket not bound"))?;
        let socket = UnixDatagram::from_std(socket)?;

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let quit = self.quit.clone();

        tokio::select! {
            result = Self::wait_socket_signal(socket, quit.clone()) => {
                result?;
                info!("Received quit signal via socket");
            }
            // SIGTERM signal from systemd
            _ = sigterm.recv() => {
                quit.store(true, Ordering::SeqCst);
                info!("Received SIGTERM, exiting...");
            }
            // SIGINT (Ctrl-C): same graceful path as SIGTERM so cleanup
            // (route/DNS rollback, iptables teardown) still runs.
            _ = sigint.recv() => {
                quit.store(true, Ordering::SeqCst);
                info!("Received SIGINT, exiting...");
            }
        }

        Ok(())
    }

    async fn wait_socket_signal(socket: UnixDatagram, quit: Arc<AtomicBool>) -> anyhow::Result<()> {
        let mut buf = [0; 1];
        loop {
            let (len, _) = socket.recv_from(&mut buf).await?;
            if len == 1 && buf[0] == 1 {
                quit.store(true, Ordering::SeqCst);
                break;
            }
        }
        Ok(())
    }

    pub fn send_quit_signal(&self) -> anyhow::Result<()> {
        let path = Path::new(&self.sock_path);
        let socket = std::os::unix::net::UnixDatagram::unbound()?;
        let _r = socket.send_to(&[1], path)?;
        println!("Send quit signal successfully.");
        std::thread::sleep(Duration::from_millis(2000));
        Ok(())
    }

    pub fn is_exited(&self) -> bool {
        self.quit.load(Ordering::SeqCst)
    }
}

impl Drop for SysSignal {
    fn drop(&mut self) {
        // Unlink while still holding the instance lock, and only if the path
        // still names our socket. Sender-side handles never own this path.
        if let Some(identity) = self.socket_identity
            && let Ok(metadata) = std::fs::symlink_metadata(&self.sock_path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == identity
        {
            std::fs::remove_file(&self.sock_path).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        process::{Child, Command, Stdio},
        sync::atomic::AtomicUsize,
    };

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "vault-control-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> String {
            self.0.join("control.socket").to_str().unwrap().into()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn assert_reachable(owner: &SysSignal) {
        let sender = std::os::unix::net::UnixDatagram::unbound().unwrap();
        sender.send_to(&[7], &owner.sock_path).unwrap();
        let mut byte = [0];
        owner
            .socket
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .recv(&mut byte)
            .unwrap();
        assert_eq!(byte, [7]);
    }

    #[test]
    fn duplicate_start_keeps_socket() {
        let fixture = Fixture::new();
        let owner = SysSignal::bind(fixture.path()).unwrap();
        let before = std::fs::symlink_metadata(fixture.path()).unwrap();
        assert!(SysSignal::bind(fixture.path()).is_err());
        let after = std::fs::symlink_metadata(fixture.path()).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_reachable(&owner);
        drop(SysSignal::new(fixture.path()));
        assert_reachable(&owner);
    }

    #[test]
    fn legacy_socket_protection() {
        let fixture = Fixture::new();
        let old = std::os::unix::net::UnixDatagram::bind(fixture.path()).unwrap();
        assert!(SysSignal::bind(fixture.path()).is_err());
        let sender = std::os::unix::net::UnixDatagram::unbound().unwrap();
        sender.send_to(&[7], fixture.path()).unwrap();
        let mut byte = [0];
        old.recv(&mut byte).unwrap();
        assert_eq!(byte, [7]);
    }

    #[test]
    fn stale_socket_cleanup() {
        let fixture = Fixture::new();
        drop(std::os::unix::net::UnixDatagram::bind(fixture.path()).unwrap());
        let owner = SysSignal::bind(fixture.path()).unwrap();
        assert_reachable(&owner);
        let lock_path = format!("{}.lock", fixture.path());
        let inode = std::fs::metadata(&lock_path).unwrap().ino();
        drop(owner);
        assert!(!Path::new(&fixture.path()).exists());
        let next = SysSignal::bind(fixture.path()).unwrap();
        assert_eq!(std::fs::metadata(lock_path).unwrap().ino(), inode);
        assert_reachable(&next);
    }

    #[test]
    fn does_not_delete_files_or_symlinks() {
        let fixture = Fixture::new();
        std::fs::write(fixture.path(), "keep").unwrap();
        assert!(SysSignal::bind(fixture.path()).is_err());
        assert_eq!(std::fs::read_to_string(fixture.path()).unwrap(), "keep");
        let linked = fixture.0.join("linked.socket");
        std::os::unix::fs::symlink(fixture.path(), &linked).unwrap();
        assert!(SysSignal::bind(linked.to_str().unwrap().into()).is_err());
        assert!(
            std::fs::symlink_metadata(linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    fn child(fixture: &Fixture) -> Child {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "signal::tests::lock_child", "--nocapture"])
            .env("VAULT_SIGNAL_TEST_PATH", fixture.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "child exited before acquiring lock"
            );
            if line.trim() == "READY" {
                break;
            }
        }
        // Keep stdout open until the test harness in the child exits.
        child.stdout = Some(reader.into_inner());
        child
    }

    #[test]
    fn lock_child() {
        let Ok(path) = std::env::var("VAULT_SIGNAL_TEST_PATH") else {
            return;
        };
        let owner = SysSignal::bind(path).unwrap();
        println!("READY");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0]).unwrap();
        assert_reachable(&owner);
    }

    #[test]
    fn lock_process_exclusion() {
        let fixture = Fixture::new();
        let mut child = child(&fixture);
        assert!(SysSignal::bind(fixture.path()).is_err());
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert!(child.wait().unwrap().success());
        let owner = SysSignal::bind(fixture.path()).unwrap();
        assert_reachable(&owner);
    }

    #[test]
    fn killed_process_recovery() {
        let fixture = Fixture::new();
        let mut child = child(&fixture);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(Path::new(&fixture.path()).exists());
        let owner = SysSignal::bind(fixture.path()).unwrap();
        assert_reachable(&owner);
    }
}
