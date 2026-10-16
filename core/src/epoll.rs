// SPDX-License-Identifier: MIT
use std::io;
use std::os::fd::RawFd;

pub enum WaitResult {
    Timeout,
    Socket,
    Device,
    Error(io::Error),
}

/// Events fetched per epoll_wait call.
const MAX_EVENTS: usize = 16;

pub struct EpollWait {
    poll_fd: RawFd,
    events: [libc::epoll_event; MAX_EVENTS],
    /// Events returned by the last epoll_wait, and how many were consumed.
    ready: usize,
    index: usize,
    socket: RawFd,
    device: RawFd,
    timeout: u32,
}

impl EpollWait {
    pub fn new(socket: RawFd, device: RawFd, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, libc::EPOLLIN as u32)
    }

    fn create(socket: RawFd, device: RawFd, timeout: u32, flags: u32) -> io::Result<Self> {
        let mut event = libc::epoll_event { u64: 0, events: 0 };
        // SAFETY: `epoll_create1` has no preconditions; the returned fd is
        // checked below and owned by Self (closed in Drop). CLOEXEC keeps the
        // fd from leaking into exec'd children (daemonize path).
        let poll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if poll_fd == -1 {
            return Err(io::Error::last_os_error());
        }
        for fd in &[socket, device] {
            event.u64 = *fd as u64;
            event.events = flags;
            // SAFETY: `poll_fd` is valid, `fd` refers to a live fd owned by the
            // caller, and `event` points to a valid stack struct.
            let res = unsafe { libc::epoll_ctl(poll_fd, libc::EPOLL_CTL_ADD, *fd, &mut event) };
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            poll_fd,
            events: [libc::epoll_event { u64: 0, events: 0 }; MAX_EVENTS],
            ready: 0,
            index: 0,
            socket,
            device,
            timeout,
        })
    }
}

impl Drop for EpollWait {
    fn drop(&mut self) {
        // SAFETY: `poll_fd` is owned by self and closed exactly once here.
        unsafe { libc::close(self.poll_fd) };
    }
}

impl Iterator for EpollWait {
    type Item = WaitResult;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.ready {
            // SAFETY: `poll_fd` is valid and `self.events` is a valid,
            // exclusively-owned buffer receiving up to MAX_EVENTS events.
            let n = unsafe {
                libc::epoll_wait(
                    self.poll_fd,
                    self.events.as_mut_ptr(),
                    MAX_EVENTS as i32,
                    self.timeout as i32,
                )
            };
            if n == -1 {
                return Some(WaitResult::Error(io::Error::last_os_error()));
            }
            if n == 0 {
                return Some(WaitResult::Timeout);
            }
            self.ready = n as usize;
            self.index = 0;
        }
        let event = self.events[self.index];
        self.index += 1;
        Some(if event.u64 == self.socket as u64 {
            WaitResult::Socket
        } else if event.u64 == self.device as u64 {
            WaitResult::Device
        } else {
            // Provably unreachable: only these two fds are ever registered
            // with the epoll instance (see create()).
            unreachable!()
        })
    }
}
