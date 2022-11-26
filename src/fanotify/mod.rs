#![allow(dead_code)]

use std::mem::{MaybeUninit, size_of};
use std::os::unix::io::{RawFd, AsRawFd, FromRawFd};
use std::ptr;
use nix::unistd::{read, write, Pid};
use nix::Result;
use nix::NixPath;
use bitflags::bitflags;
use nix::errno::Errno;


pub const FANOTIFY_METADATA_VERSION: u8 = 3;

pub const FAN_NOFD: i32 = -1;
pub const FAN_NOPIDFD: i32 = FAN_NOFD;
pub const FAN_EPIDFD: i32 = -2;

pub const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
pub const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;
pub const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;
pub const FAN_EVENT_INFO_TYPE_ERROR: u8 = 5;


bitflags! {
    /// Configuration options for [`fanotify_init`](https://man7.org/linux/man-pages/man2/fanotify_init.2.html).
    pub struct InitFlags: libc::c_uint {
        /// Allow the receipt of events notifying that a file has been accessed and events for 
        /// permission decisions if a file may be accessed. It is intended for event
        /// listeners that need to access files before they contain their final data.
        /// 
        /// Use of this flag requires the `CAP_SYS_ADMIN capability`.
        const FAN_CLASS_PRE_CONTENT = libc::FAN_CLASS_PRE_CONTENT;

        /// Allow the receipt of events notifying that a file has been accessed and 
        /// events for permission decisions if a file may be accessed. It is intended for event
        /// listeners that need to access files when they already contain their final content. 
        ///
        /// Use of this flag requires the `CAP_SYS_ADMIN` capability.
        const FAN_CLASS_CONTENT = libc::FAN_CLASS_CONTENT;

        /// This is the default value. It does not need to be specified. This value only allows
        /// the receipt of events notifying that a file has been accessed. Permission decisions
        /// before the file is accessed are not possible.
        const FAN_CLASS_NOTIF = libc::FAN_CLASS_NOTIF;

        /// Set the close-on-exec flag (`FD_CLOEXEC`) on the new file descriptor. See the 
        /// description of the `O_CLOEXEC` flag in `open(2)`.
        const FAN_CLOEXEC = libc::FAN_CLOEXEC;
        
        /// Enable the nonblocking flag (`O_NONBLOCK`) for the file descriptor. Reading from the
        /// file descriptor will not block. Instead, if no data is available, `read(2)` fails 
        /// with the error `EAGAIN`.
        const FAN_NONBLOCK = libc::FAN_NONBLOCK;

        /// Remove the limit on the number of events in the event queue. See `fanotify(7)` for
        /// details about this limit.
        /// 
        /// Use of this flag requires the `CAP_SYS_ADMIN` capability.
        const FAN_UNLIMITED_QUEUE = libc::FAN_UNLIMITED_QUEUE;
        
        /// Remove the limit on the number of fanotify marks per user. See `fanotify(7)` for details about this limit.
        /// 
        /// Use of this flag requires the `CAP_SYS_ADMIN` capability.
        const FAN_UNLIMITED_MARKS = libc::FAN_UNLIMITED_MARKS;

        /// *(since Linux 4.20)*
        /// 
        /// Report  thread  ID  (TID)  instead of process ID (PID) in the pid field of the struct
        /// `fanotify_event_metadata` supplied to `read(2)` (see `fanotify(7)`). 
        /// 
        /// Use of this flag 
        /// requires the `CAP_SYS_ADMIN` capability.
        const FAN_REPORT_TID = 0x00000100; // linux/fanotify.h::FAN_REPORT_TID

        /// *(since Linux 4.15)*
        /// 
        /// Enable generation of audit log records about access mediation performed by permission events.
        /// 
        /// The permission event response has to be marked with the `FAN_AUDIT` flag for an audit log
        /// record to be generated.
        /// 
        /// Use of this flag requires the `CAP_AUDIT_WRITE` capability.
        const FAN_ENABLE_AUDIT = 0x00000040;

        /// *(since Linux 5.1)*
        /// 
        /// Allow the receipt of events which contain additional information about the underlying
        /// filesystem object correlated to an event. See `fanotify(7)` for additional details.
        const FAN_REPORT_FID = 0x00000200;

        /// *(since Linux 5.9)*
        /// 
        /// Events for fanotify groups initialized with this flag will contain additional
        /// information about a directory object correlated to an event.
        const FAN_REPORT_DIR_FID = 0x00000400;

        /// *(since Linux 5.9)*
        /// 
        /// Events for fanotify groups initialized with this flag will contain additional information about the 
        /// name of the directory entry correlated to an event.
        /// 
        /// This flag must be provided in conjunction with the
        /// flag FAN_REPORT_DIR_FID. Providing this flag value without `FAN_REPORT_DIR_FID` will result in the error
        /// `EINVAL`. 
        /// 
        /// This flag may be combined with the flag `FAN_REPORT_FID`.
        const FAN_REPORT_NAME = 0x00000800;

        /// *(since Linux 5.9)* 
        /// 
        /// This is a synonym for `FAN_REPORT_DIR_FID | FAN_REPORT_NAME`.
        const FAN_REPORT_DFID_NAME = Self::FAN_REPORT_DIR_FID.bits | Self::FAN_REPORT_NAME.bits;

        /// *(since Linux 5.17)*
        /// 
        /// Events for fanotify groups initialized with this flag will contain additional information about the
        /// child correlated with directory entry modification events. This flag
        /// must be provided in conjunction with the flags `FAN_REPORT_FID`, `FAN_REPORT_DIR_FID` and `FAN_REPORT_NAME`,
        /// or else the error `EINVAL` will be returned. See `fanotify(7)` for additional details.
        const FAN_REPORT_TARGET_FID = 0x00001000;

        /// *(since Linux 5.17)*
        /// 
        /// This is a synonym for `FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID`.
        const FAN_REPORT_DFID_NAME_TARGET = 
            Self::FAN_REPORT_DFID_NAME.bits | Self::FAN_REPORT_TARGET_FID.bits | Self::FAN_REPORT_TARGET_FID.bits;
        
        /// *(since Linux 5.15)*
        /// 
        /// Events for fanotify groups initialized with this flag will contain an additional information
        /// record alongside the generic fanotify_event_metadata structure. For more details on 
        /// information records, see `fanotify(7)`.
        const FAN_REPORT_PIDFD = 0x00000080;
    }
}

bitflags! {
    pub struct MarkFlags: libc::c_uint {
        /// If pathname is a symbolic link, mark the link itself
        /// 
        /// By default, fanotify_mark() dereferences pathname if it is a symbolic link.
        const FAN_MARK_DONT_FOLLOW = libc::FAN_MARK_DONT_FOLLOW;
    
        /// If the filesystem object to be marked is not a directory, the error ENOTDIR shall be raised.
        const FAN_MARK_ONLYDIR = libc::FAN_MARK_ONLYDIR;
        
        /// Mark the mount specified by pathname.
        /// 
        /// Requires the CAP_SYS_ADMIN capability.
        const FAN_MARK_MOUNT = libc::FAN_MARK_MOUNT;

        /// *(since Linux 4.20)*
        /// 
        /// Mark the filesystem specified by pathname.
        /// 
        /// Requires the CAP_SYS_ADMIN capability.
        const FAN_MARK_FILESYSTEM = libc::FAN_MARK_FILESYSTEM;

        /// The  events in mask shall be added to or removed from the ignore mask.
        const FAN_MARK_IGNORED_MASK = libc::FAN_MARK_IGNORED_MASK;

        /// The ignore mask shall survive modify events.
        const FAN_MARK_IGNORED_SURV_MODIFY = libc::FAN_MARK_IGNORED_SURV_MODIFY;
    }
}

bitflags! {
    pub struct Response: u32 {
        const FAN_ALLOW = libc::FAN_ALLOW;

        const FAN_DENY = libc::FAN_DENY;

        /// Bit mask to create audit record for result
        const FAN_AUDIT = 0x10;
    }
}

bitflags! {
    pub struct EventFlags: u64 {
        /// A file or directory is accessed (`read`).
        const FAN_ACCESS = libc::FAN_ACCESS;
        
        /// A file is modified (`write`).
        const FAN_MODIFY = libc::FAN_MODIFY;
        
        /// A writable file is closed.
        const FAN_CLOSE_WRITE = libc::FAN_CLOSE_WRITE;
        
        /// A read-only file or directory is closed.
        const FAN_CLOSE_NOWRITE = libc::FAN_CLOSE_NOWRITE;
        
        /// A file or directory is opened.
        const FAN_OPEN = libc::FAN_OPEN;
        
        /// *(since Linux 5.0)*
        /// 
        /// A file is opened with the intent to be executed.
        const FAN_OPEN_EXEC = 0x00001000;

        /// *(since Linux 5.1)*
        /// 
        /// The metadata for a file or directory has changed.
        /// 
        /// An fanotify group that identifies filesystem objects by file handles is required.
        const FAN_ATTRIB = 0x00000004;

        /// *(since Linux 5.1)*
        /// 
        /// A file or directory has been created in a marked parent directory.
        /// 
        /// An fanotify group that identifies filesystem objects by file handles is required.
        const FAN_CREATE = 0x00000100;
        
        /// *(since Linux 5.1)*
        /// 
        /// A file or directory has been deleted in a marked parent directory.
        ///  
        /// An fanotify group that identifies filesystem objects by file handles is required.
        const FAN_DELETE = 0x00000200;

        /// *(since Linux 5.1)*
        /// 
        /// A marked file or directory itself is deleted.
        /// 
        /// A fanotify group that identifies filesystem objects by file handles is required.
        const FAN_DELETE_SELF = 0x00000400;

        /// *(since Linux 5.16)*
        /// 
        /// A filesystem error leading to inconsistent filesystem metadata is detected.
        /// 
        /// A fanotify group that 
        /// identifies filesystem objects by file handles is required.
        /// 
        /// Events of such type are dependent on 
        /// support from the underlying filesystem.
        const FAN_FS_ERROR = 0x00008000;

        /// *(since Linux 5.1)*
        /// 
        /// A file or directory has been moved from a marked parent directory. 
        /// 
        /// A fanotify group that identifies filesystem objects by file handles is required.
        const FAN_MOVED_FROM = 0x00000040;

        /// *(since Linux 5.1)*
        /// 
        /// A file or directory has been moved to a marked parent directory. 
        /// 
        /// A fanotify group that identifies filesystem objects by file handles is required.
        const FAN_MOVED_TO = 0x00000080;

        /// *(since Linux 5.17)*
        /// 
        /// File was renamed.
        /// 
        /// A fanotify  group  that identifies filesystem objects by file handles 
        /// is required. If the filesystem object to be marked is not a directory, the error `ENOTDIR` shall be
        /// raised.
        const FAN_RENAME = 0x10000000;

        /// *(since Linux 5.1)*
        /// 
        /// A marked file or directory itself has been moved.
        /// 
        /// A fanotify group that identifies filesystem
        /// objects by file handles is required.
        const FAN_MOVE_SELF = 0x00000800;

        /// A permission to open a file or directory is requested.
        /// 
        /// A fanotify file descriptor created 
        /// with `FAN_CLASS_PRE_CONTEN` or `FAN_CLASS_CONTENT` is required.
        const FAN_OPEN_PERM = libc::FAN_OPEN_PERM;

        /// *(since Linux 5.0)*
        /// 
        /// Create  an  event when a permission to open a file for execution is requested.
        /// 
        /// A fanotify file descriptor created with FAN_CLASS_PRE_CONTENT or FAN_CLASS_CONTENT is 
        /// required.  See NOTES for additional details.
        const FAN_OPEN_EXEC_PERM = 0x00040000;

        /// Create an event when a permission to read a file or directory is requested. 
        /// 
        /// A fanotify file descriptor created with FAN_CLASS_PRE_CONTENT or FAN_CLASS_CONTENT 
        /// is required.
        const FAN_ACCESS_PERM = libc::FAN_ACCESS_PERM;

        /// Create  events for directories—for example, when opendir(3), readdir(3) (but see BUGS), and closedir(3) are called.  Without this flag, events are created only for files.
        /// In the context of directory entry events, such as FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM, and FAN_MOVED_TO, specifying the flag FAN_ONDIR is required in order  to  create
        /// events when subdirectory entries are modified (i.e., mkdir(2)/ rmdir(2)).
        const FAN_ONDIR = libc::FAN_ONDIR;

        /// Events for the immediate children of marked directories shall be created.
        const FAN_EVENT_ON_CHILD = libc::FAN_EVENT_ON_CHILD;

        /// A file is closed 
        /// 
        /// This is synonimous to`FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE`.
        const FAN_CLOSE = libc::FAN_CLOSE;
        
        /// A file or directory has been moved 
        /// 
        /// This is synonimous to `FAN_MOVED_FROM | FAN_MOVED_TO`.
        const FAN_MOVE = Self::FAN_MOVED_FROM.bits | Self::FAN_MOVED_TO.bits;

        /// Event queued overflowed.
        const FAN_Q_OVERFLOW = 0x00004000;
    }
}

bitflags! {
    pub struct OpenFlags: libc::c_uint {
        /// This value allows only read access.
        const O_RDONLY = libc::O_RDONLY as libc::c_uint;

        /// This value allows only read access.
        const O_WRONLY = libc::O_WRONLY as libc::c_uint;

        /// This value allows read and write access.
        const O_RDWR = libc::O_RDWR as libc::c_uint;

        /// Enable  support  for  files exceeding 2 GB.
        const O_LARGEFILE = libc::O_LARGEFILE as libc::c_uint;

        /// *(since Linux 3.18)*
        /// 
        /// Enable the close-on-exec flag for the file descriptor.
        const O_CLOEXEC = libc::O_CLOEXEC as libc::c_uint;

    }
}

/// A fanotify instance. This is also a file descriptor, so you can 
/// feed it to other interfaces consuming file descriptors, like 
/// `poll` or `epoll`.
#[derive(Debug, Clone, Copy)]
pub struct Fanotify {
    fd: RawFd
}

#[derive(Debug, Clone)]
pub struct FanotifyEventMetadata {
    /// Length of the data for the current event and the
    /// offset to the next event in the buffer.
    pub event_len: u32,

    /// A version number for the structure. It must
    /// be compared to `FANOTIFY_METADATA_VERSION`.
    pub vers: u8,

    /// This is the length of the structure.
    pub metadata_len: u16,

    /// This is a bit mask describing the event (see below).
    pub mask: EventFlags,

    /// Open file descriptor for the object being accessed, or `FAN_NOFD` if a queue overflow occurred.  
    /// The reading application is responsible for closing this file descriptor.
    pub fd: RawFd,

    /// PID of the process that caused the event.
    /// If flag `FAN_REPORT_TID` was set, this is
    /// the TID of the thread that caused the event.
    pub pid: Pid,
}


impl Fanotify {
    /// Initialize a new `Fanotify` instance.
    /// 
    /// Returns a `Result` containing a fanotify instance.
    /// 
    /// For more information, see [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html).
    pub fn fanotify_init(flags: InitFlags, event_f_flags: OpenFlags) -> Result<Fanotify> {
        let res = Errno::result( 
            unsafe {
                libc::fanotify_init(flags.bits(), event_f_flags.bits())
            }
        );
        res.map(|fd| Fanotify { fd })
    }
    
    fn fanotify_mark<P: ?Sized + NixPath>(
        self,
        flags: libc::c_uint,
        mask: EventFlags,
        dirfd: RawFd,
        path: &P
    ) -> Result<()> {
        let res = path.with_nix_path(|cstr| {
            unsafe {
                libc::fanotify_mark(self.fd, flags, mask.bits(), dirfd, cstr.as_ptr())
            }
        })?;
        Errno::result(res).map(drop)
    }

    /// Add the events contained in `mask` to the mark mask (or to the ignore mask).
    pub fn add_mark<P: ?Sized + NixPath>(
        self,
        flags: MarkFlags,
        mask: EventFlags,
        dirfd: RawFd,
        path: &P
    ) -> Result<()> {
        self.fanotify_mark(libc::FAN_MARK_ADD | flags.bits(), mask, dirfd, path)
    }

    /// Remove the events contained in `mask` from the mark mask (or from the ignore mask).
    pub fn remove_mark<P: ?Sized + NixPath>(
        self,
        flags: MarkFlags,
        mask: EventFlags,
        dirfd: RawFd,
        path: &P
    ) -> Result<()> {
        self.fanotify_mark(libc::FAN_MARK_REMOVE | flags.bits(), mask, dirfd, path)
    }

    /// Remove either all marks for filesystems, all marks for mounts, or all marks
    /// for directories and files from the fanotify group.
    pub fn flush_marks<P: ?Sized + NixPath>(
        self,
        flags: MarkFlags,
        mask: EventFlags,
        dirfd: RawFd,
        path: &P
    ) -> Result<()> {
        self.fanotify_mark(libc::FAN_MARK_FLUSH | flags.bits(), mask, dirfd, path)
    }
    
    /// Reads a collection of events from the fanotify group descriptor. This call
    /// can either be blocking or non blocking depending on whether `FAN_NONBLOCK`
    /// was set at initialization.
    ///
    /// Returns as many events as available. If the call was non blocking and no
    /// events could be read then the `EAGAIN` error is returned.
    pub fn read_events(self) -> Result<Vec<FanotifyEventMetadata>> {
        let metadata_size = size_of::<libc::fanotify_event_metadata>();
        const BUFSIZ: usize = 4096;
        let mut buffer = [0u8; BUFSIZ];
        let mut events = Vec::new();
        let mut offset = 0;
        
        let nread = read(self.fd, &mut buffer)?;

        while (nread - offset) >= metadata_size {
            let event = unsafe {
                let mut event = MaybeUninit::<libc::fanotify_event_metadata>::uninit();
                ptr::copy_nonoverlapping( // Equivalent to libc::memcpy(), as opposed to ptr::copy() <=> libc::memmove()
                    buffer.as_ptr().add(offset),
                    event.as_mut_ptr() as *mut u8,
                    metadata_size
                );
                event.assume_init()
            };
            events.push(FanotifyEventMetadata{
                event_len: event.event_len,
                vers: event.vers,
                metadata_len: event.metadata_len,
                mask: EventFlags { bits: event.mask },
                fd: event.fd,
                pid: Pid::from_raw(event.pid),
            });
            offset += event.event_len as usize;
        }
        Ok(events)
    }

    /// Write response to the underlying file descriptor
    ///
    /// Needed for `FAN_OPEN_PERM` and `FAN_OPEN_EXEC_PERM` events.
    pub fn respond(self, fd: RawFd, response: Response) -> Result<usize> {
        let resp_struct = libc::fanotify_response{
            fd: fd,
            response: response.bits(),
        };
        let mut buffer = [0u8; size_of::<libc::fanotify_response>()];
        unsafe {
            ptr::copy_nonoverlapping(
                &resp_struct as *const libc::fanotify_response as *const u8, 
                buffer.as_mut_ptr(),
                buffer.len())
        };
        write(self.fd, &buffer)
    }
}

impl AsRawFd for Fanotify {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl FromRawFd for Fanotify {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Fanotify { fd }
    }
}
