use std::{env, process};
use std::collections::HashMap;
use nix;
use nix::unistd::Pid;

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
    let (fanotify, fds) = prepare_input(argv[1].as_str()).expect("Fanotify init");
    println!("Listening for events.");
    let proc_table: HashMap<Pid, ProcStats> = HashMap::new();
    loop_until_input_recieved(fanotify, fds, proc_table).expect("Looping through events");
    println!("Listening for events stopped.");
}
