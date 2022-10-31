use std::{env, os::unix::prelude::RawFd, process, path::*, str::FromStr, fs};
use libc;
use nix::{self, poll::{self, PollFlags}, errno::*};
use fanotify::low_level::*;

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


fn fanotify_respond(fd: i32, resp_fd: i32, resp_response: u32) -> Result<usize, Errno> {
    let mut response = resp_fd.to_ne_bytes().to_vec();
    let mut code = resp_response.to_ne_bytes().to_vec();
    response.append(&mut code);
    nix::unistd::write(fd, &response)
}

fn handle_event(metadata: &fanotify_event_metadata, fd: i32) {
    /* Check that run-time and compile-time structures match. */
    if metadata.vers != FANOTIFY_METADATA_VERSION {
        println!("Mismatch of fanotify metadata version.");
        process::exit(1);
    }
    /* metadata->fd contains either FAN_NOFD, indicating a
    queue overflow, or a file descriptor (a nonnegative
    integer). Here, we simply ignore queue overflow. */
    if metadata.fd >= 0 {
        /* Handle open permission event. */
        if (metadata.mask & FAN_OPEN_PERM) != 0 {
            print!("FAN_OPEN_PERM: ");
            fanotify_respond(fd, metadata.fd, FAN_ALLOW)
                .expect("Cannot write response");
        }
        if (metadata.mask & FAN_OPEN_EXEC_PERM) != 0 {
            print!("FAN_OPEN_PERM: ");
            fanotify_respond(fd, metadata.fd, FAN_ALLOW)
                .expect("Cannot write response");
        }
        /* Handle closing of writable file event. */
        if (metadata.mask & FAN_CLOSE_WRITE) != 0 {
            print!("FAN_CLOSE_WRITE: ");
        }
        /* Handle closing of nowritable file event. */
        if (metadata.mask & FAN_CLOSE_NOWRITE) != 0 {
            print!("FAN_CLOSE_NOWRITE: ");
        }
        /* Retrieve and print pathname of the accessed file. */
        let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
        procfd_path.push(metadata.fd.to_string());
        let procname = match fs::read_link(procfd_path) {
            Ok(path) => path,
            Err(_) => std::path::PathBuf::from("[unknown file]"),
        };
        println!("File {} PID {}", procname.display(), metadata.pid);
        /* Close the file descriptor of the event. */
        close_fd(metadata.fd);
    }

}

fn handle_events(fd: RawFd) {
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
        /* FAN_EVENT_OK macro checks the remaining length len of the buffer
           meta against the length of the metadata structure and the
           event_len field of the first metadata structure in the
           buffer.*/
        while fan_event_ok(metadata, len) {
            unsafe {
                handle_event(&*metadata, fd);
                /* Advance to next event. */
                /* FAN_EVENT_NEXT macro uses the length indicated in the event_len
                field of the fanotify_event_metadata structure pointed to by metadata to
                calculate the address of the next fanotify_event_metadata structure that
                follows meta. len is the number of bytes of fanotify_event_metadata that
                currently remain in the buffer. The macro returns a pointer to the next
                fanotify_event_metadata structure that follows metadata,
                and reduces len by the number of bytes in the fanotify_event_metadata
                structure that has been skipped over(i.e., it subtracts
                metadata->event_len from len). */
                metadata = fan_event_next(&*metadata, &mut len);
            }
        }
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(16, 0);

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
    /* Mark the mount for:
       - permission events before opening files
       - notification events after closing a write-enabled and nowriteble 
         file descriptor. */
    fanotify_mark(fd,
        FAN_MARK_ADD | FAN_MARK_MOUNT,
        FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE,
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
                /* Console input is available: empty stdin and quit. */
                //while std::io::stdin().read(buf.as_mut()).expect("Cannot read stdin") > 0 {
                //    continue; 
                //}
                break;
            }
            if fds[1].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                /* Fanotify events are available. */
                handle_events(fd);
            }
        }
    }
    println!("Listening for events stopped.");
}
