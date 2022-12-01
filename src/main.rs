#![warn(clippy::all, clippy::pedantic)]
#![warn(nonstandard_style)]
#![warn(rust_2018_idioms)]

use std::{env, process};
use exitcode;

mod fanotify;
mod scanning;
mod config;
mod main_loop;

fn main() {
    let argv = env::args().collect::<Vec<_>>();
    if argv.len() != 2 {
        process::exit(exitcode::USAGE);
    }
    main_loop::start(&argv[1]);
}
