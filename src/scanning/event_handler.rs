use std::collections::HashMap;
use std::{process, fs, str::FromStr};
use std::path::{PathBuf, Path};
use std::time::{self, SystemTime};
use nix::unistd::{self, Pid};
use nix::errno::Errno;
use nix::sys::signal;
use log;

use crate::fanotify::{self, Fanotify, EventFlags};
use crate::scanning::proc_stats::ProcStats;
use crate::scanning::distance::{distance, Distance};
use crate::config::Config;
use crate::db_manager::DbManager;


/// Main appllication struct that collects process stats
/// and handles `fanotify` events according to these stats
/// and data from the database.
pub struct EventHandler {
    proc_table: HashMap<Pid, ProcStats>,
    config: Config,
    db: DbManager,
}

/// A simple struct that holds process ID
/// and parent ID together
#[derive(Debug, Clone, Copy)]
struct ProcessIds {
    pid: Pid,
    parent_id: Pid
}

/// This `enum` is the returned by the `database_check`
/// function to tell if the executable is present in the
/// allow list, deny list or not present in the database.
enum DbCheckResult {
    Trusted,
    MaybeSuspicious,
    DefSuspicious,
}

impl EventHandler {
    /// Creates a new `EventHandler` instance with the given config
    pub fn with_config(config: Config) -> EventHandler {
        let db = if config.enable_allowlist {
            match DbManager::new(config.allowlist_path.as_path()) {
                Ok(manager) => manager,
                Err(e) => {
                    log::warn!("failed to load database file {} : {}", config.allowlist_path.display(), e);
                    DbManager::default()
                }
            }

        } else {
            DbManager::default()
        };
        EventHandler {
            proc_table: HashMap::new(), 
            config,
            db,
        }
    }

    /// Read all available events from fanotify instance
    /// and handle them accordingly.
    pub fn handle_events(&mut self, fanotify: Fanotify) -> nix::Result<()> {
        // Loop while events can be read from fanotify file descriptor.
        loop {
            // Read some events.
            let events = match fanotify.read_events() {
                Ok(vec) => vec,
                Err(Errno::EAGAIN) => break,
                Err(code) => return Err(code)
            };
            // Loop over all events in the buffer.
            for event in &events {
                self.handle_event(event, fanotify)?;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self, timeout: std::time::Duration) {
        let now = SystemTime::now();
        self.proc_table.retain(|_, stats| {
            now.duration_since(stats.last_update_time).unwrap_or(time::Duration::ZERO) < timeout
        });
    }
    

    /// Send response to the process that tries to open a file
    /// If process is known ans suspicious, `FAN_DENY` is sent,
    /// `FAN_ALLOW` otherwise.
    /// With the given approach read-only processes don't need
    /// to be held in the process table.
    fn handle_open_perm(
        &self,
        metadata: &fanotify::EventMetadata,
        fanotify: Fanotify
    ) -> nix::Result<()> {
        let response = if let Some(process) = self.proc_table.get(&metadata.pid) {
            if process.susness > self.config.critical_susp  {
                fanotify::Response::FAN_DENY
            } else {
                fanotify::Response::FAN_ALLOW
            }
        } else {
            fanotify::Response::FAN_ALLOW
        };
        fanotify.respond(metadata.fd, response)?;
        Ok(())
    }

    /// Modify suspiciousness value of the already known process (see source below),
    /// or add a new process to the table.
    /// If the process is suspicious, `kill_process_and_related` is called.
    fn handle_modify_event(&mut self, metadata: &fanotify::EventMetadata) -> nix::Result<()> {
        let maybe_path = get_path_by_pid(metadata.pid);
        if let Ok(path) = &maybe_path {
            match self.db_check(path.as_path()) {
                DbCheckResult::Trusted => return Ok(()),
                DbCheckResult::DefSuspicious => {
                    self.kill_process_and_related(metadata.pid);
                    return Ok(());
                }
                DbCheckResult::MaybeSuspicious => {}
            }
        }
        // Retirieve write statistics for that process
        let proc_stats = if let Some(val) = self.proc_table.get_mut(&metadata.pid) {
            val
        } else {
            self.proc_table.insert(metadata.pid, ProcStats::new());
            self.proc_table.get_mut(&metadata.pid).unwrap()
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
        if proc_stats.susness > self.config.critical_susp {
            if let Ok(path) = &maybe_path {
                if let Err(e) = self.db.add_to_denylist(path.as_path()) {
                    log::warn!("Cannot access database file: {}", e);
                }
            }
            self.kill_process_and_related(metadata.pid);
            self.proc_table.remove(&metadata.pid);
        }
        Ok(())
    }

    /// Handle incoming `fanotify` event. For more information, see
    /// `handle_open_perm` and `handle_modify_event`.
    fn handle_event(
        &mut self,
        metadata: &fanotify::EventMetadata,
        fanotify: Fanotify,
    ) -> nix::Result<()> {
        // Check that run-time and compile-time structures match.
        if metadata.vers != fanotify::FANOTIFY_METADATA_VERSION {
            log::error!("Fatal error: mismatch of fanotify metadata version.");
            process::exit(1);
        }
        if metadata.fd >= 0 {
            if metadata.mask.contains(EventFlags::FAN_OPEN_PERM) ||
               metadata.mask.contains(EventFlags::FAN_OPEN_EXEC_PERM) {
                self.handle_open_perm(metadata, fanotify)?;
            }
            if metadata.mask.contains(EventFlags::FAN_CLOSE_WRITE) {
                self.handle_modify_event(metadata)?;
            }
            unistd::close(metadata.fd).unwrap_or_default();
        }
        Ok(())
    }

    /// This function tries to kill all process children, as well as
    /// the parent process unless it is init (pid = 1)
    /// The function does not return errno, instead it writes error messages
    /// to stderr and stdout.
    fn kill_process_and_related(&self, pid: Pid) {
        let signal = if self.config.use_sigterm {signal::SIGTERM} else {signal::SIGKILL};
        // if true - kill all process group
        // if any processes left - kill them
        if self.config.kill_proc_group {
            kill_process_group(pid, signal);
            log::trace!("Killing remaining processes...");
        }
        // kill all child processes and the parent process:
        if let Ok(proc_table) = get_process_table() {
            // Kill parent process
            if let Ok(i) = proc_table.binary_search_by(|probe| probe.pid.cmp(&pid)) {
                if self.config.kill_parent && proc_table[i].parent_id.as_raw() != 1 {
                    kill_process(proc_table[i].parent_id, signal);
                }
            }
            if self.config.kill_children {
                kill_descendants(pid, &proc_table, signal);
            }
        } else {
            log::warn!("Error: cannot access /proc");
        }
        // Kill the process itself
        kill_process(pid, signal);
    }


    /// Check if the executable specified by `path`
    /// is present in the allow list, deny list or not present in the database.
    fn db_check(&self, path: &Path) -> DbCheckResult {
        match self.db.allowlist_contains(path) {
            Ok(true) => return DbCheckResult::Trusted,
            Ok(false) => {},
            Err(e) => {
                log::warn!("Cannot access database file: {}", e);
                return DbCheckResult::MaybeSuspicious;
            }
        }
        match self.db.denylist_contains(path) {
            Ok(true) => DbCheckResult::DefSuspicious,
            Ok(false) => DbCheckResult::MaybeSuspicious,
            Err(e) => {
                log::warn!("Cannot access database file: {}", e);
                DbCheckResult::MaybeSuspicious
            }
        }
    }

}


/// Get all process id's available in `/proc` together with their
/// parent id's.
/// 
/// This function may get extended and improved in future.
fn get_process_table() -> std::io::Result<Vec<ProcessIds>> {
    let iterator = fs::read_dir("/proc")?;
    let table = iterator // we get a directory iterator
        .filter(Result::is_ok) // keep only good results
        .map(|x| x.unwrap().path()) // take only paths
        .filter(|path| // and keep only those that end with a non-negative integer
            path.file_name().unwrap().to_str().unwrap().chars().all(char::is_numeric))
        .map(|mut path| { // read everything from /proc/[pid]/stat
            path.push("stat");
            fs::read_to_string(path)
        })
        .filter(Result::is_ok) // keep only good results
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

/// Read file name from the fanotify event file descriptor
fn get_path_by_fd(fd: i32) -> nix::Result<PathBuf> {
    let mut procfd_path = PathBuf::from_str("/proc/self/fd").unwrap();
    procfd_path.push(fd.to_string());
    fs::read_link(procfd_path)
        .map_err(|err| { // If failed => convert the error to nix::Errno and send it back to the caller
        Errno::from_i32(err.raw_os_error().unwrap_or_default())
    })
}

/// This function tries to kill the process.
/// All open calls from the process will be blocked until it's killed.
/// The function does not return errno, instead it writes error messages
/// to stderr and stdout.
fn kill_process(pid: Pid, signal: signal::Signal) {
    log::trace!("Killing {pid}...");
    if let Err(code) = signal::kill(pid, signal) {
        log::warn!("Error: cannot send signal to process {pid} : {code}");
    }
}

/// This function tries to kill the process group specified by id.
/// All open calls from the processes will be blocked until they are killed.
/// The function does not return errno, instead it writes error messages
/// to stderr and stdout.
fn kill_process_group(pid: Pid, signal: signal::Signal) {
    log::trace!("Killing process group {pid}...");
    let pg_id =  Pid::from_raw(-pid.as_raw());
    if let Err(code) = signal::kill(pg_id, signal) {
        log::warn!("Error: cannot kill process group {pid} : {code}");
    }
}

/// This function tries to all processes that are descendants to `pid`.
/// All open calls from the process will be blocked until it's killed.
/// The function does not return errno, instead it writes error messages
/// to stderr and stdout.
fn kill_descendants(pid: Pid, proc_table: &Vec<ProcessIds>, signal: signal::Signal) {
    for proc in proc_table {
        if proc.parent_id == pid {
            kill_process(proc.pid, signal);
            kill_descendants(proc.pid, proc_table, signal);
        }
    }
}


/// Read get path to the executable of the process specified by
/// `pid` by accessing the `/proc` pseudofilesystem.
fn get_path_by_pid(pid: Pid) -> std::io::Result<PathBuf> {
    let mut link_to_exe = PathBuf::from_str("/proc").unwrap();
    link_to_exe.push(pid.to_string());
    link_to_exe.push("exe");
    fs::read_link(link_to_exe)
}
