use std::os::unix::prelude::{RawFd, AsRawFd};
use std::time::Duration;
use nix::poll::{PollFd, PollFlags, poll};
use nix::errno::Errno;

use crate::config::Config;
use crate::fanotify::{Fanotify, OpenFlags, InitFlags, MarkFlags, EventFlags};
use crate::scanning::event_handler::EventHandler;

// ~~~~~~~ Hard-coded constant ~~~~~~~
const FLUSH_PERIOD: u32 = 64;


/// Initialize fanotify instance with appropriate flags and marks
/// and return it with the descriptors needed for `poll`.
pub fn prepare_input(path: &str) -> nix::Result<(Fanotify, [PollFd; 2])> {
    let fanotify = Fanotify::fanotify_init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_PRE_CONTENT | InitFlags::FAN_NONBLOCK,
        OpenFlags::O_RDONLY | OpenFlags::O_LARGEFILE)?;
    fanotify.add_mark(MarkFlags::FAN_MARK_MOUNT,
        EventFlags::FAN_CLOSE_WRITE | EventFlags::FAN_OPEN_PERM | EventFlags::FAN_OPEN_EXEC_PERM,
        libc::AT_FDCWD,
        path)?;
    let fds = [
        PollFd::new(libc::STDIN_FILENO as RawFd, PollFlags::POLLIN),
        PollFd::new(fanotify.as_raw_fd(), PollFlags::POLLIN),
    ];
    Ok((fanotify, fds))
}

/// Process all fanotify events as they are available
/// until some input from standard input is recieved.
pub fn loop_until_input_recieved(
    fanotify: Fanotify,
    mut fds: [PollFd; 2],
    config: Config
) -> nix::Result<()> {
    let mut flush_counter = 0u32;
    let flust_timeout = Duration::from_secs(config.flush_timeout_sec);
    let mut handler = EventHandler::with_config(config);
    loop {
        let poll_num = match poll(&mut fds, -1) {
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
            Ok(val) => val,
        };
        if poll_num > 0 {
            if fds[0].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                break;
            }
            if fds[1].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                // Fanotify events are available.
                flush_counter += 1;
                handler.handle_events(fanotify)?;
                if flush_counter > FLUSH_PERIOD {
                    handler.flush(flust_timeout);
                    flush_counter = 0;
                }
            }
        }
    }
    Ok(())
}
