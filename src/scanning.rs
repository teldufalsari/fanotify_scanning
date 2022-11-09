use std::path::*;
use std::vec::Vec;
use std::{process, str::FromStr, fs};
use std::os::unix::prelude::{RawFd, AsRawFd};
use std::collections::HashMap;
use nix::{self, errno::*};
use nix::sys::signal;
use nix::unistd::{self, Pid};
use nix::poll::{poll, PollFd, PollFlags};
use libc;

use crate::fanotify_wrappers::*;

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ PUBLIC ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/// Initialize fanotify instance with appropriate flags and marks
/// and return it with the descriptors needed for `poll`.
pub fn prepare_input(path: &str) -> nix::Result<(Fanotify, [PollFd; 2])> {
    let fanotify = Fanotify::fanotify_init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_PRE_CONTENT | InitFlags::FAN_NONBLOCK,
        OpenFlags::O_RDONLY | OpenFlags::O_LARGEFILE)?;
    fanotify.add_mark(MarkFlags::FAN_MARK_MOUNT,
        EventFlags::FAN_MODIFY | EventFlags::FAN_OPEN_PERM | EventFlags::FAN_OPEN_EXEC_PERM,
        libc::AT_FDCWD,
        path)?;
    let fds = [
        PollFd::new(libc::STDIN_FILENO as RawFd, PollFlags::POLLIN),
        PollFd::new(fanotify.as_raw_fd(), PollFlags::POLLIN),
    ];
    return Ok((fanotify, fds));
}

/// Process all fanotify events as they are available
/// until some input from standard input is recieved.
pub fn loop_until_input_recieved(
    fanotify: Fanotify,
    mut fds: [PollFd; 2],
    mut proc_table: HashMap<Pid, ProcStats>
) -> nix::Result<()> {
    loop {
        let poll_num = poll(&mut fds, -1)?;
        if poll_num > 0 {
            if fds[0].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                break;
            }
            if fds[1].revents().unwrap_or(PollFlags::empty()).contains(PollFlags::POLLIN) {
                // Fanotify events are available.
                handle_events(fanotify, &mut proc_table)?;
            }
        }
    }
    Ok(())
}


/// This structure contains a field that measures how
/// suspicious this process is and stores all file paths
/// that were modified by this process.
#[derive(Debug, Clone)]
pub struct ProcStats {
    pub susness : i32,
    pub paths: Vec<PathBuf>,
}

impl ProcStats {
    /// Creates an empty record with zero fields.
    pub fn new() -> ProcStats {
        ProcStats {
            susness: 0,
            paths: Vec::new(),
        }
    }
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ PRIVATE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

enum Distance {
    Zero,
    SameDir,
    NeigbourDirs,
    Far,
}

/// Max value of susness field that processes are allowed to have.
///  If this value is exceeded, the process is killed.
const CRITICAL_SUSNESS: i32 = 5; 

///  Find "distance" between two absolute paths.
fn distance(path1: &Path, path2: &Path) -> Distance {
    if path1.eq(path2) {
        return Distance::Zero;
    }
    let parent1 = path1.parent().unwrap();
    let parent2 = path2.parent().unwrap();
    if parent1.eq(parent2) {
        return Distance::SameDir;
    } else {
        let pparent1 = parent1.parent();
        let pparent2 = parent2.parent();
        if pparent1 != None {
            if pparent2 != None {
                if pparent1.unwrap().eq(pparent2.unwrap()) {
                    return  Distance::NeigbourDirs;
                }
            } else { // pparent2 = None
                if pparent1.unwrap().eq(parent2) {
                    return  Distance::NeigbourDirs;
                }
            }
        } else {
            // pparent1 = None, pparent2 is not None
            // Because if both  pparent1 and pparent2 are None,
            // parent1 and parent2 are both "/" and thus parent1.eq(parent2) is true,
            // but it's not since it's been already checked above.
            if parent1.eq(pparent2.unwrap()) {
                return  Distance::NeigbourDirs;
            }
        }
    }
    Distance::Far
}

fn kill_process(pid: Pid) {
    // First remove the executable (at least try)
    println!("Found malicious process, PID={}", pid);
    let mut link_to_exe = PathBuf::from_str("/proc").unwrap();
    link_to_exe.push(pid.to_string());
    link_to_exe.push("exe");
    let path_to_exe = fs::read_link(link_to_exe).unwrap(); // need to check unwrap and print something like (cannot locate process executable)
    println!("Removing execulable \"{}\"...", path_to_exe.display());
    match fs::remove_file(path_to_exe) {
        Ok(_) => println!("Done."),
        Err(_) =>  println!("It's invincible!"),
    };
    // Then kill the wrongdoer
    println!("Killing process now...");
    match signal::kill(pid, signal::SIGKILL) {
        Ok(_) => println!("Done"),
        Err(_) => println!("I can't even kill it. Why?..."),
    }
}

fn handle_open_perm(
    metadata: &FanotifyEventMetadata,
    fanotify: Fanotify,
    proc_table: &mut HashMap<Pid, ProcStats>
) -> nix::Result<()> {
    let response = if let Some(process) = proc_table.get(&metadata.pid) {
        if process.susness > CRITICAL_SUSNESS {
            Response::FAN_DENY
        } else {
            Response::FAN_ALLOW
        }
    } else {
        Response::FAN_ALLOW
    };
    fanotify.respond(metadata.fd, response)?;
    Ok(())
}

fn handle_modify_event(
    metadata: &FanotifyEventMetadata,
    proc_table: &mut HashMap<Pid, ProcStats>
) -> nix::Result<()> {
    // Retirieve write statistics for that process
    let proc_stats = match proc_table.get_mut(&metadata.pid) {
        Some(val) => val,
        None => {
            proc_table.insert(metadata.pid, ProcStats::new());
            proc_table.get_mut(&metadata.pid).unwrap()
        }
    };
    if proc_stats.paths.is_empty() {
        // If it's a new process, retrieve the modified
        // file name and add it to the paths vector
        let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
        procfd_path.push(metadata.fd.to_string());
        let file_name = fs::read_link(procfd_path).unwrap(); // Don't unwrap!!!!!!!!!!!!
        proc_stats.paths.push(file_name);
    } else {
        // If the process is already in the table, we need to
        // retrieve the name of the file modified
        let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
        procfd_path.push(metadata.fd.to_string());
        let path1buf = fs::read_link(procfd_path).unwrap(); // Don't unwrap!!!!!!!!!!!!!!

        if proc_stats.paths.contains(&path1buf) {
            // If process writes to the same file again, it's less suspicious
            if proc_stats.susness > 0 {proc_stats.susness -= 1}

        } else {
            // If the files are different, we decide how close they are to each other.
            // The closer paths are, the more it's suspicious
            let path2 = proc_stats.paths.last().unwrap().as_path();

            match distance(path1buf.as_path(), path2) {
                Distance::Zero => {if proc_stats.susness > 0 {proc_stats.susness -= 1}},
                Distance::SameDir => proc_stats.susness += 2,
                Distance::NeigbourDirs => proc_stats.susness += 1,
                Distance::Far => ()
            };

            // Save this path for future analysis
            proc_stats.paths.push(path1buf);
        }
    }
    if proc_stats.susness > CRITICAL_SUSNESS {
        kill_process(metadata.pid);
        proc_table.remove(&metadata.pid);
    }
    Ok(())
}

fn handle_event(
    metadata: &FanotifyEventMetadata,
    fanotify: Fanotify,
    proc_table: &mut HashMap<Pid, ProcStats>
) -> nix::Result<()> {
    // Check that run-time and compile-time structures match.
    if metadata.vers != FANOTIFY_METADATA_VERSION {
        eprintln!("Mismatch of fanotify metadata version.");
        process::exit(1);
    }
    if metadata.fd >= 0 {
        if metadata.mask.contains(EventFlags::FAN_OPEN_PERM) || metadata.mask.contains(EventFlags::FAN_OPEN_EXEC_PERM) {
            handle_open_perm(metadata, fanotify, proc_table)?;
        }
        if metadata.mask.contains(EventFlags::FAN_MODIFY) {
            handle_modify_event(metadata, proc_table)?;
        }
        unistd::close(metadata.fd).unwrap_or_default();
    }
    Ok(())
}

/// Read all available events from fanotify instance
/// and handle them accordingly.
pub fn handle_events(fanotify: Fanotify, proc_table: &mut HashMap<Pid, ProcStats>) -> nix::Result<()> {
    // Loop while events can be read from fanotify file descriptor.
    loop {
        // Read some events.
        let events = match fanotify.read_events() {
            Ok(vec) => vec,
            Err(Errno::EAGAIN) => break,
            Err(code) => {
                println!("Read from fanotify failed: {}", code.to_string());
                process::exit(code as i32);
            }
        };
        // Loop over all events in the buffer.
        for event in events.iter() {
            handle_event(event, fanotify, proc_table)?;
        }
    }
    Ok(())
}
