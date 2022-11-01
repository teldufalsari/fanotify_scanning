use std::{env, os::unix::prelude::RawFd, process, path::*, str::FromStr, fs};
use std::collections::HashMap;
use libc;
use nix::{self, poll::{self, PollFlags}, errno::*};
use fanotify::low_level::*;
mod scanning;
use scanning::scanning::*;

/*
  For some reason the library on crates.io
  does not contain this definiton, but the open-source
  on github.com does. I'll include lib sources
  as a dependency in future.
*/
const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;

/*
  Rust doesn't have compile-time sizeof()'s like C does.
  But don't you worry, this value is used only to
  initialize a buffer that could fit approx. 200
  of those structures, which are generally
  variable-sized. In case presice size is
  needed, runtime std::mem::size_of is used.
*/
const SIZEOF_FAN_METADATA: usize = 24;



fn _fanotify_respond(fd: i32, resp_fd: i32, resp_response: u32) -> Result<usize, Errno> {
    let mut response = resp_fd.to_ne_bytes().to_vec();
    let mut code = resp_response.to_ne_bytes().to_vec();
    response.append(&mut code);
    nix::unistd::write(fd, &response)
}

fn decimate_mercilessly(pid: i32) {
    // First remove the executable (at least try)
    println!("Found malicious process, PID={}", pid);
    let mut link_to_exe = PathBuf::from_str("/proc").unwrap();
    link_to_exe.push(pid.to_string());
    link_to_exe.push("exe");
    let path_to_exe = fs::read_link(link_to_exe).unwrap(); // need to check unwrap
    println!("Removing execulable \"{}\"...", path_to_exe.display());
    match fs::remove_file(path_to_exe) {
        Ok(_) => println!("Done."),
        Err(_) =>  println!("It's invincible!"),
    };
    // Then kill the wrongdoer
    println!("Killing process now...");
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGKILL) {
        Ok(_) => println!("Done"),
        Err(_) => println!("I can't even kill it. Why?..."),
    }
}

fn handle_event(metadata: &fanotify_event_metadata, _fd: i32, proc_table: &mut HashMap<i32, ProcStats>) {
    /* Check that run-time and compile-time structures match. */
    if metadata.vers != FANOTIFY_METADATA_VERSION {
        println!("Mismatch of fanotify metadata version.");
        process::exit(1);
    }
    /* metadata->fd contains either FAN_NOFD, indicating a
    queue overflow, or a file descriptor (a nonnegative
    integer). Here, we simply ignore queue overflow. */
    if metadata.fd >= 0 {
        if (metadata.mask & FAN_MODIFY) != 0 {
            // Retirieve write statistics for that process
            let proc_stats = match proc_table.get_mut(&metadata.pid) {
                Some(val) => val,
                None => {
                    proc_table.insert(metadata.pid, ProcStats::new());
                    proc_table.get_mut(&metadata.pid).unwrap()
                }
            };
            if proc_stats.paths.is_empty() { // If it's a new process
                // Retrieve the modified file name and add it to the paths vector
                let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
                procfd_path.push(metadata.fd.to_string());
                let file_name = fs::read_link(procfd_path).unwrap();
                proc_stats.paths.push(file_name);
            } else { // The process is already in the table
                // Retirive the modified accessed file name
                let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
                procfd_path.push(metadata.fd.to_string());
                let path1buf = fs::read_link(procfd_path).unwrap();
                if proc_stats.paths.contains(&path1buf) {
                    // If process writes to the same file again, it's less suspicious
                    if proc_stats.susness > 0 {proc_stats.susness -= 1}
                } else {
                    // The closer paths are, the more it's suspicious
                    let path2 = proc_stats.paths.last().unwrap().as_path();
                    match distance(path1buf.as_path(), path2) {
                        Distance::Zero => {if proc_stats.susness > 0 {proc_stats.susness -= 1}},
                        Distance::SameDir => proc_stats.susness += 2,
                        Distance::NeigbourDirs => proc_stats.susness += 1,
                        Distance::Far => ()
                    };
                    proc_stats.paths.push(path1buf);
                }
            }
            if proc_stats.susness > CRITICAL_SUSNESS {
                decimate_mercilessly(metadata.pid);
                proc_table.remove(&metadata.pid);
            }
        }
        close_fd(metadata.fd);
    }

}

fn handle_events(fd: RawFd, info: &mut HashMap<i32, ProcStats>) {
    /* Helper functions to deal with fanotify_event_metadata buffers */
    fn fan_event_ok(meta: *const fanotify_event_metadata, len: usize) -> bool {
        let size_of_struct = std::mem::size_of::<fanotify_event_metadata>();
        unsafe {
            len >= size_of_struct &&
            (*meta).event_len as usize >= size_of_struct &&
            (*meta).event_len as usize <= len
        }
    }
    fn fan_event_next(meta: &fanotify_event_metadata, len: &mut usize) -> *const fanotify_event_metadata {
        *len -= meta.event_len as usize;
        let ptr: *const fanotify_event_metadata = meta;
        unsafe { ptr.offset(meta.event_len as isize) }
    }

    let mut buf = [0u8; SIZEOF_FAN_METADATA * 200];
    /* Loop while events can be read from fanotify file descriptor. */
    loop {
        /* Read some events. */
        let mut len = match nix::unistd::read(fd, &mut buf) {
            Ok(val) => val,
            Err(Errno::EAGAIN) => 0,
            Err(_) => {
                println!("Cannot read fanotify");
                process::exit(1)
            }
        };
        /* Check if end of available data reached. */
        if len == 0 { break; }
        /* Point to the first event in the buffer. */
        let mut metadata = buf.as_ptr() as *const fanotify_event_metadata;
        /* Loop over all events in the buffer. */
        while fan_event_ok(metadata, len) {
            unsafe {
                handle_event(&*metadata, fd, info);
                /* Advance to next event. */
                metadata = fan_event_next(&*metadata, &mut len);
            }
        }
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut operations_info: HashMap<i32, ProcStats> = HashMap::new();

    /* Check mount point is supplied. */
    if argv.len() != 2 {
        println!("Usage: {} MOUNT", argv[0]);
        process::exit(1);
    }
    println!("Listening to the directory {}", argv[1]);
    /* Create the file descriptor for accessing the fanotify API. */
    let fd = fanotify_init(
        FAN_CLOEXEC | FAN_CLASS_PRE_CONTENT | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE)
        .expect("fanotify_init failed");
    fanotify_mark(fd,
        FAN_MARK_ADD | FAN_MARK_MOUNT,
        FAN_MODIFY,
        AT_FDCWD,
        argv[1].as_str())
        .expect("fanotify_mark failed");
    /* Prepare for polling. */
    let mut fds = [
        poll::PollFd::new(libc::STDIN_FILENO as RawFd, poll::PollFlags::POLLIN),
        poll::PollFd::new(fd as RawFd, poll::PollFlags::POLLIN),
    ];
    println!("Listening for events");
    /* This is the loop to wait for incoming events. */
    loop {
        let poll_num = match poll::poll(&mut fds, -1) {
            Ok(val) => val,
            Err(Errno::EINTR) => continue,
            Err(_) => {
                println!("poll failed");
                process::exit(1);
            }
        };
        if poll_num > 0 {
            if fds[0].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                break;
            }
            if fds[1].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                /* Fanotify events are available. */
                handle_events(fd, &mut operations_info);
            }
        }
    }
    println!("Listening for events stopped.");
}
