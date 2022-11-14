use std::{env, process};
use std::collections::HashMap;
use nix::unistd::Pid;
use nix::errno::Errno;

mod scanning;
mod fanotify_wrappers;

use scanning::*;


fn main() {
    let argv: Vec<String> = env::args().collect();
    // Check mount point is supplied.
    if argv.len() != 2 {
        println!("Usage: {} MOUNT", argv[0]);
        process::exit(1);
    }
    // Create the file descriptor for accessing the fanotify API and prepare for polling.
    let (fanotify, fds) = match prepare_input(argv[1].as_str()) {
        Ok(val) => val,
        Err(Errno::EPERM) => {
            println!("Operation not permitted. Rerun as root.");
            process::exit(1);
        }
        Err(code) => {
            eprintln!("Error: {}", code.desc());
            process::exit(1);
        }
    };
    // Run main listening loop.
    println!("Listening for events.");
    let proc_table: HashMap<Pid, ProcStats> = HashMap::new();
    if let Err(code) = loop_until_input_recieved(fanotify, fds, proc_table) {
        eprintln!("Error: {}", code.desc());
        process::exit(1);
    }
    println!("Listening for events stopped.");
}
