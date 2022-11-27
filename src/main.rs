#![warn(clippy::all, clippy::pedantic)]
#![warn(nonstandard_style)]
#![warn(rust_2018_idioms)]

use std::{env, process};
use nix::errno::Errno;

use crate::config::Config;
use crate::scanning::main_loop::{
    prepare_fanotify,
    loop_until_input_recieved,
};

mod fanotify;
mod scanning;
mod config;

fn main() {
    let argv: Vec<String> = env::args().collect();
    // Check mount point is supplied.
    if argv.len() != 2 {
        println!("Usage: {} MOUNT", argv[0]);
        process::exit(1);
    }
    // load config
    let config = match Config::load() {
        Ok(c) => c,
        Err(descr) => {
            print!("Cannot read config file: {}\nFalling back to defaults\n", descr);
            Config::default()
        }
    };

    // Create a file descriptor for accessing the fanotify API and prepare for polling.
    let fanotify = match prepare_fanotify(argv[1].as_str()) {
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
    if let Err(code) = loop_until_input_recieved(fanotify, config) {
        eprintln!("Error: {}", code.desc());
        process::exit(1);
    }
}
