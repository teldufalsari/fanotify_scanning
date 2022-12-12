#![warn(clippy::all, clippy::pedantic)]
#![warn(nonstandard_style)]
#![warn(rust_2018_idioms)]

mod fanotify;
mod scanning;
mod config;
mod main_loop;
mod daemonizer;
mod db_manager;

fn main() {
    main_loop::start("/");
}
