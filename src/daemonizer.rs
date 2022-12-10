use std::os::unix::prelude::*;
use std::path::Path;
use std::process;
use std::time::Duration;

use nix::{self, unistd};
use nix::sys::stat::{self, Mode};
use nix::fcntl::{self, FcntlArg, OFlag};
use anyhow::{self, Context};

#[allow(clippy::cast_possible_truncation)]
fn lockfile(fd: RawFd) -> nix::Result<i32> {
    let fl = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_start: 0,
        l_whence: libc::SEEK_SET as i16,
        l_len: 0,
        l_pid: 0,
    };
    let arg = FcntlArg::F_SETLK(&fl);
    fcntl::fcntl(fd, arg)
}

#[allow(clippy::cast_possible_truncation)]
fn close_range(first: u32, last: u32) -> nix::Result<()> {
    nix::errno::Errno::result(
        unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first as libc::c_uint,
                last as libc::c_uint,
                0
            ) as i32 // this cast is safe because close_range returns i32
        }
    ).map(drop)
}

fn create_pid_file(path: &Path) -> anyhow::Result<()> {
    let oflag = OFlag::O_RDWR | OFlag::O_CREAT;
    let mode = Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IROTH;
    let fd = fcntl::open(path, oflag, mode)?;
    lockfile(fd)?;
    unistd::ftruncate(fd, 0)?;
    let pid_str = process::id().to_string() + "\0";
    unistd::write(fd, pid_str.as_bytes()).map(drop).with_context(|| "write")
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
pub fn daemonize(path_to_pid_file: &Path) -> anyhow::Result<()> {
    let retry_timeout = Duration::from_millis(20);

    let outcome = unsafe { unistd::fork().with_context(|| "fork")? };
    if outcome.is_parent() {
        process::exit(0)
    }
    unistd::setsid().with_context(|| "setsid")?;
    let ppid = unistd::getpid();

    let outcome = unsafe { unistd::fork().with_context(|| "fork")? };
    if outcome.is_parent() {
        process::exit(0)
    }
    stat::umask(Mode::empty());
    unistd::chdir("/")?;
    let max_fd = nix::unistd::sysconf(unistd::SysconfVar::OPEN_MAX)
        .with_context(|| "sysconf")?
        .unwrap().clamp(0, i64::from(u32::MAX)) as u32;
    close_range(0, max_fd).with_context(|| "close")?;

    let fd0 = fcntl::open("/dev/null", OFlag::O_RDWR, Mode::empty())
        .with_context(|| "open \"/dev/null\"")?;
    if libc::STDIN_FILENO != fd0 {
        return Err(anyhow::Error::msg(
            format!("fd0({}) is not equal to STDOUT_FILENO{}",
            fd0,
            libc::STDOUT_FILENO
        )));
    }
    unistd::dup2(fd0, libc::STDOUT_FILENO)
        .with_context(|| "dup2")?;
    unistd::dup2(fd0, libc::STDERR_FILENO)
        .with_context(|| "dup2")?;
    while unistd::getppid() == ppid {
        std::thread::sleep(retry_timeout);
    }
    create_pid_file(path_to_pid_file).with_context(|| "daemon is already running")
}