use std::os::unix::prelude::AsRawFd;
use std::time::Duration;
use nix::poll::{PollFd, PollFlags, poll};
use nix::errno::Errno;

use crate::config::Config;
use crate::fanotify::{Fanotify, OpenFlags, InitFlags, MarkFlags, EventFlags};
use crate::scanning::event_handler::EventHandler;

// ~~~~~~~ Hard-coded constant ~~~~~~~
const FLUSH_PERIOD: u32 = 64;


/// Initialize fanotify instance with appropriate flags and marks
pub fn prepare_fanotify(path: &str) -> nix::Result<Fanotify> {
    let fanotify = Fanotify::fanotify_init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_PRE_CONTENT | InitFlags::FAN_NONBLOCK,
        OpenFlags::O_RDONLY | OpenFlags::O_LARGEFILE)?;
    fanotify.add_mark(
        MarkFlags::FAN_MARK_MOUNT,
        EventFlags::FAN_CLOSE_WRITE | EventFlags::FAN_OPEN_PERM | EventFlags::FAN_OPEN_EXEC_PERM,
        libc::AT_FDCWD,
        path)?;
    Ok(fanotify)
}

/// Process all fanotify events as they are available.
/// 
/// Loops infinitely as a main loop of every daemon should
pub fn loop_until_input_recieved(fanotify: Fanotify, config: Config) -> nix::Result<()> {
    let mut flush_counter = 0u32;
    let flush_timeout = Duration::from_secs(config.flush_timeout_sec);
    let mut handler = EventHandler::with_config(config);
    let mut poll_fd = [PollFd::new(fanotify.as_raw_fd(), PollFlags::POLLIN)];
    loop {
        let poll_num = match poll(&mut poll_fd, -1) {
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
            Ok(val) => val,
        };
        if poll_num > 0 {
            // Fanotify events are available.
            flush_counter += 1;
            handler.handle_events(fanotify)?;
            if flush_counter > FLUSH_PERIOD {
                handler.flush(flush_timeout);
                flush_counter = 0;
            }
        }
    }
}
