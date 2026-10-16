// SPDX-License-Identifier: MIT
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::net::UnixDatagram;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

pub struct SysSignal {
    sock_path: String,
    quit: Arc<AtomicBool>,
    // Bound up front (before privilege dropping makes /run unwritable);
    // taken and converted to a tokio socket by init().
    socket: Mutex<Option<std::os::unix::net::UnixDatagram>>,
}

impl SysSignal {
    /// Sender-side handle (e.g. `-s quit`): holds only the path and must
    /// never bind — binding would unlink the running instance's socket.
    pub fn new(sock_path: String) -> Self {
        Self {
            sock_path,
            quit: Arc::new(AtomicBool::new(false)),
            socket: Mutex::new(None),
        }
    }

    /// Receiver-side handle: binds the control socket immediately, so it can
    /// be created while still privileged (/run is root-owned).
    pub fn bind(sock_path: String) -> anyhow::Result<Self> {
        let path = std::path::Path::new(&sock_path);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let socket = std::os::unix::net::UnixDatagram::bind(path)?;
        socket.set_nonblocking(true)?;
        // Owner/group only: a world-writable control socket would let any
        // local user shut the daemon down. Root and the daemon's own user
        // (e.g. after privilege dropping) can both still send the quit byte.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(Self {
            sock_path,
            quit: Arc::new(AtomicBool::new(false)),
            socket: Mutex::new(Some(socket)),
        })
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
        let sock_path = self.sock_path.clone();

        tokio::select! {
            _ = Self::wait_socket_signal(socket, quit.clone(), sock_path) => {
                info!("Received quit signal via socket");
            }
            // SIGTERM signal from systemd
            _ = sigterm.recv() => {
                quit.store(true, Ordering::SeqCst);
                std::fs::remove_file(&self.sock_path).ok();
                info!("Received SIGTERM, exiting...");
            }
            // SIGINT (Ctrl-C): same graceful path as SIGTERM so cleanup
            // (route/DNS rollback, iptables teardown) still runs.
            _ = sigint.recv() => {
                quit.store(true, Ordering::SeqCst);
                std::fs::remove_file(&self.sock_path).ok();
                info!("Received SIGINT, exiting...");
            }
        }

        Ok(())
    }

    async fn wait_socket_signal(
        socket: UnixDatagram,
        quit: Arc<AtomicBool>,
        sock_path: String,
    ) -> anyhow::Result<()> {
        let mut buf = [0; 1];
        loop {
            let r = socket.recv_from(&mut buf).await;
            if let Ok((_len, _addr)) = r
                && buf[0] == 1
            {
                quit.store(true, Ordering::SeqCst);
                break;
            }
        }
        std::fs::remove_file(sock_path).ok();
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

    pub fn exit(&self) {
        self.quit.store(true, Ordering::SeqCst);
    }

    pub fn is_exited(&self) -> bool {
        self.quit.load(Ordering::SeqCst)
    }
}
