# Krom
Proof-of-concept virus scanning utility using fanotify

## Build
Make sure you have Rust toolchain installed. To install the utility run `install.sh` from `etc` directory.

## Usage

If you have krom installe in your system, it can be managed as any other systemd service. Enter

`systemctl start kromd` - to run the service

`systemctl status kromd` - to show status and log

`systemctl stop kromd` - to terminate service

`systemctl enable kromd` - to enable autostart after system startup (Don't use if you haven't configured allow list in the proc_data.db!)

`systemctl disable kromd` - to disable autostart

You can also run standalone binaries:

`./scanner [mount point]` - watch for all i/o events in the directory (must be run as root)

`./cryptor [directory]` - recursively encrypt all regular files in the directory
