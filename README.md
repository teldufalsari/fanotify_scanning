# fanotify_scanning
Proof-of-concept virus scanning utility using fanotify

Usage:

`./scanner [directory]` - watch for all i/o events in the directory (must be run with as root)

`./cryptor [directory]` - recursively encrypt all regular files in the directory
