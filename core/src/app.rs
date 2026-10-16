// SPDX-License-Identifier: MIT
use std::{fs, sync::Arc};

use clap::Parser;
use serde::de::DeserializeOwned;
use tracing::info;

use crate::{SysSignal, try_fail};

#[derive(Parser, Debug, Default)]
struct Args {
    /// Read configuration options from the specified file.
    #[arg(long)]
    config: Option<String>,

    /// Print debug information
    #[arg(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Only print errors and warnings
    #[arg(short, long)]
    quiet: bool,

    /// Print the version and exit
    #[arg(long)]
    version: bool,

    /// Run the process in the background
    #[arg(long)]
    daemon: bool,

    /// Store the process id in this file when daemonizing
    #[arg(long)]
    pid_file: Option<String>,

    /// Run as other user
    #[arg(long)]
    user: Option<String>,

    /// Run as other group
    #[arg(long)]
    group: Option<String>,

    /// Print logs also to files in this directory
    #[arg(long)]
    log_dir: Option<String>,

    #[arg(short)]
    s: Option<String>,
}

/// Deferred privilege-drop request handed to the do_run closure. The caller
/// applies it after all root-only initialization (TUN device, iptables,
/// resolv.conf) and before entering the run loop. With no --user/--group it
/// is a no-op.
pub struct PrivDropRequest {
    user: Option<String>,
    group: Option<String>,
}

impl PrivDropRequest {
    pub fn apply(self) -> anyhow::Result<()> {
        if self.user.is_none() && self.group.is_none() {
            return Ok(());
        }
        info!("Dropping privileges");
        drop_privileges(self.user.as_deref(), self.group.as_deref())
    }
}

#[cfg(target_os = "linux")]
fn drop_privileges(user: Option<&str>, group: Option<&str>) -> anyhow::Result<()> {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    // PR_SET_KEEPCAPS: keep the permitted set across the UID change;
    // privdrop would otherwise clear it.
    caps::securebits::set_keepcaps(true)?;
    let mut pd = privdrop::PrivDrop::default();
    if let Some(user) = user {
        pd = pd.user(user);
    }
    if let Some(group) = group {
        pd = pd.group(group);
    }
    pd.apply()?;

    // Re-arm exactly the capabilities the daemons still need: NET_ADMIN for
    // TUN/route/iptables management, NET_RAW for raw packet sockets, and
    // DAC_OVERRIDE so the edge client can rewrite the root-owned
    // /etc/resolv.conf on exit.
    let wanted: HashSet<Capability> = [
        Capability::CAP_NET_ADMIN,
        Capability::CAP_NET_RAW,
        Capability::CAP_DAC_OVERRIDE,
    ]
    .into_iter()
    .collect();
    caps::set(None, CapSet::Permitted, &wanted)?;
    caps::set(None, CapSet::Effective, &wanted)?;
    for cap in &wanted {
        caps::raise(None, CapSet::Ambient, *cap)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_privileges(user: Option<&str>, group: Option<&str>) -> anyhow::Result<()> {
    // Linux capabilities do not exist elsewhere; plain UID/GID change.
    let mut pd = privdrop::PrivDrop::default();
    if let Some(user) = user {
        pd = pd.user(user);
    }
    if let Some(group) = group {
        pd = pd.group(group);
    }
    pd.apply()?;
    Ok(())
}

pub fn app_main<T: DeserializeOwned, F, F2>(
    name: &str,
    logger_init: F,
    do_run: F2,
) -> anyhow::Result<()>
where
    F: FnOnce(bool, bool, Option<&String>) -> anyhow::Result<()>,
    F2: FnOnce(Arc<SysSignal>, T, PrivDropRequest) -> anyhow::Result<()>,
{
    let args: Args = Args::parse();
    if args.version {
        println!("Vault v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let sock_path = format!("/run/{name}.socket");

    if let Some(s) = &args.s
        && s.eq("quit")
    {
        // Sender side: only the path is needed; binding here would unlink
        // the running instance's socket.
        let signal = SysSignal::new(sock_path);
        let r = signal.send_quit_signal();
        if let Err(e) = r {
            println!("Send quit signal error. {}", e);
        }
        return Ok(());
    }

    if args.daemon {
        let mut daemonize = daemonize::Daemonize::new();
        if let Some(pid_file) = &args.pid_file {
            daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
        }
        // --user/--group are NOT set on the daemonizer: the fork keeps root
        // privileges so TUN/iptables setup can still run; the do_run closure
        // applies the deferred privilege drop itself once initialization is
        // done.
        try_fail!(daemonize.start(), "Failed to daemonize: {}");
        // The logger must start after the fork: the non-blocking file
        // writer's background thread does not survive daemonize, so a
        // logger created earlier would silently stop writing.
        logger_init(args.verbose, args.quiet, args.log_dir.as_ref())?;
        info!("Running process as daemon");
    } else {
        logger_init(args.verbose, args.quiet, args.log_dir.as_ref())?;
    }

    if args.config.is_none() {
        println!("Config file must be given as parameter");
        return Ok(());
    }

    // Bind the control socket now, before any privilege drop: /run is
    // root-owned and only writable here.
    let signal: Arc<SysSignal> = Arc::new(SysSignal::bind(sock_path)?);

    let config_path = args.config.unwrap();

    let content: String = fs::read_to_string(config_path)?;
    let config: T = toml::from_str(&content)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("vault")
        .build()?;

    let signal_init = signal.clone();
    rt.spawn(async move { signal_init.init().await });

    let privdrop = PrivDropRequest {
        user: args.user,
        group: args.group,
    };
    rt.block_on(async move { do_run(signal, config, privdrop) })?;

    Ok(())
}
