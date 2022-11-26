use std::collections::HashMap;
use std::{process, fs, str::FromStr};
use std::path::PathBuf;
use std::time::SystemTime;
use nix::unistd::{self, Pid};
use nix::errno::Errno;
use nix::sys::signal;

use crate::fanotify::*;
use crate::scanning::proc_stats::*;
use crate::scanning::distance::*;
use crate::scanning::main_loop::CRITICAL_SUSNESS;

#[derive(Debug, Clone, Copy)]
struct ProcessIds {
    pid: Pid,
    parent_id: Pid
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
                println!("Read from fanotify failed: {code}");
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

// Send response to the process that tries to open a file
// If process is known ans suspicious, `FAN_DENY` is sent,
// `FAN_ALLOW` otherwise.
// With the given approach read-only processes don't need
// to be held in the process table.
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

/// Modify suspiciousness value of the already known process (see source below),
/// or add a new process to the table.
/// If the process is suspicious, `kill_process` is called.
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
        let file_name = get_path_by_fd(metadata.fd)?;
        proc_stats.paths.push(file_name);
    } else {
        // If the process is already in the table, we need to
        // retrieve the name of the file modified
        let path1buf = get_path_by_fd(metadata.fd)?;
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
            proc_stats.last_update_time = SystemTime::now();
        }
    }
    if proc_stats.susness > CRITICAL_SUSNESS {
        kill_process_and_related(metadata.pid);
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
        if metadata.mask.contains(EventFlags::FAN_CLOSE_WRITE) {
            handle_modify_event(metadata, proc_table)?;
        }
        unistd::close(metadata.fd).unwrap_or_default();
    }
    Ok(())
}

/// Get all process id's available in `/proc together with their
/// parent id's.
/// 
/// This function may get extended and improved in future.
fn get_process_table() -> std::io::Result<Vec<ProcessIds>> {
    let iterator = fs::read_dir("/proc")?;
    let table = iterator // we get a directory iterator
        .filter(|x| x.is_ok()) // keep only good results
        .map(|x| x.unwrap().path()) // take only paths
        .filter(|path| // and keep only those that end with a non-negative integer
            path.file_name().unwrap().to_str().unwrap().chars().all(char::is_numeric))
        .map(|mut path| { // read everything from /proc/[pid]/stat
            path.push("stat");
            fs::read_to_string(path)
        })
        .filter(|x| x.is_ok()) // keep only good results
        .map(|stat| { // read only pid and ppid from /proc/[pid]/stat contents
            let stat = stat.unwrap();
            let mut stat = stat.split(' ');
            // The first number is pid
            let pid = Pid::from_raw(stat.next().unwrap().parse::<i32>().unwrap());
            // skip nonnumerical records
            let mut stat = stat.skip_while(|x| !x.chars().all(char::is_numeric));
            // The second *numerical* record is parent pid
            let parent_id = Pid::from_raw(stat.next().unwrap().parse::<i32>().unwrap());
            ProcessIds {pid, parent_id}
        })
        .collect::<Vec<_>>(); // turbofish:D
    Ok(table)
}

// Read file name from the fanotify event file descriptor
fn get_path_by_fd(fd: i32) -> nix::Result<PathBuf> {
    let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
    procfd_path.push(fd.to_string());
    fs::read_link(procfd_path)
        .map_err(|err| { // If failed => convert the error to nix::Errno and send it back to the caller
        Errno::from_i32(err.raw_os_error().unwrap_or_default())
    })
}

// This function tries to kill the process.
// All open calls from the process will be blocked until it's killed.
// The function does not return errno, instead it writes error messages
// to stderr and stdout.
fn kill_process(pid: Pid) {
    print!("Killing {pid}...");
    if let Err(code) = signal::kill(pid, signal::SIGTERM) {
        println!("failed.");
        eprintln!("Cannot send signal to process {pid} : {code}");
    } else {
        println!("done.");
    }
}

// This function tries to all processes that are descendants to `pid`.
// All open calls from the process will be blocked until it's killed.
// The function does not return errno, instead it writes error messages
// to stderr and stdout.
fn kill_descendants(pid: Pid, proc_table: &Vec<ProcessIds>) {
    for proc in proc_table {
        if proc.parent_id == pid {
            kill_process(proc.pid);
            kill_descendants(proc.pid, proc_table)
        }
    }
}

// This function tries to kill all process children, as well as
// the parent process unless it is init (pid = 0)
// The function does not return errno, instead it writes error messages
// to stderr and stdout.
fn kill_process_and_related(pid: Pid) {
    println!("Found malicious process, PID={pid}");
    // kill all child processes and the parent process:
    if let Ok(proc_table) = get_process_table() {
        // Kill parent process
        if let Ok(i) = proc_table.binary_search_by(|probe| probe.pid.cmp(&pid)) {
            if proc_table[i].parent_id.as_raw() != 1 {
                // killing parent should be nerfed
                //kill_process(proc_table[i].parent_id);
                println!("Killing {}...done.", proc_table[i].parent_id);
            }
        }
        // now write a beautiful recursive call that will destroy child processess
        kill_descendants(pid, &proc_table);
    } else {
        println!("Cannot access /proc. Why?");
        eprintln!("Cannot access /proc");
    }
    // Kill the process itself
    // Use SIGTERM insread of SIGKILL for academic purposes
    kill_process(pid);
}
