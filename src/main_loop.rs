use std::process;
use std::path::PathBuf;
use std::os::unix::prelude::AsRawFd;
use std::str::FromStr;
use std::time::Duration;
use nix::poll::{PollFd, PollFlags, poll};
use nix::errno::Errno;
use syslog::{self, Facility, BasicLogger, Formatter3164};
use log::{self, LevelFilter};

use crate::config::Config;
use crate::daemonizer;
use crate::fanotify::{Fanotify, OpenFlags, InitFlags, MarkFlags, EventFlags};
use crate::scanning::event_handler::EventHandler;

// ~~~~~~~ Hard-coded constant ~~~~~~~
const FLUSH_PERIOD: u32 = 64;


pub fn start(mount_point: &str) {
    let pid_file_path = PathBuf::from_str("/run/kromd.pid").unwrap();
    // Try forking
    let outcome = daemonizer::daemonize(&pid_file_path);
    // Create syslog logger
    let formatter = Formatter3164 {
        facility: Facility::LOG_DAEMON,
        hostname: None,
        process: "kromd".to_owned(),
        pid: process::id(),
    };
    let logger = syslog::unix(formatter).unwrap();
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Trace)).unwrap();
    // Check if fork was successfull
    if let Err(e) = outcome {
        log::error!("start failure: {}", e);
        process::exit(exitcode::OSERR);
    }
    // Load config
    let config = if let Ok(val) = Config::load() {
        val
    } else {
        log::warn!("Cannot read config file, falling back to defaults");
        Config::default()
    };

    // Create a file descriptor for accessing the fanotify API and prepare for polling.
    let fanotify = match prepare_fanotify(mount_point) {
        Ok(val) => val,
        Err(Errno::EPERM) => {
            log::error!("Fatal error: operation not permitted. Rerun as root.");
            process::exit(exitcode::NOPERM);
        }
        Err(code) => {
            log::error!("Fatal error: {}", code.desc());
            process::exit(exitcode::OSERR);
        }
    };
    // Run main listening loop.
    log::info!("Daemon started; listening for events");
    if let Err(code) = listen_loop(fanotify, config) {
        log::error!("Fatal error: {}", code.desc());
        process::exit(exitcode::OSERR);
    }
}

/// Initialize fanotify instance with appropriate flags and marks
fn prepare_fanotify(path: &str) -> nix::Result<Fanotify> {
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
fn listen_loop(fanotify: Fanotify, config: Config) -> nix::Result<()> {
    let mut flush_counter = 0u32;
    let flush_timeout = Duration::from_secs(config.flush_timeout_sec);
    let mut handler = EventHandler::with_config(config);
    // set a no-op SIGHHUP handler (we don't have any log files)
    let sighup_handler = ||  {};
    if let Err(e) = set_sighup_handler(sighup_handler) {
        log::error!("failed to set SIGHUP handler: {}", e);
    }
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

fn set_sighup_handler<F>(handler: F) -> nix::Result<signal_hook::SigId>
where
    F: Fn() + Sync + Send + 'static
{
    unsafe {
        signal_hook::low_level::register(
            signal_hook::consts::SIGHUP,
            handler
        ).map_err(|e| 
            nix::errno::from_i32(e.raw_os_error().unwrap_or_default())
        )
    }
}
