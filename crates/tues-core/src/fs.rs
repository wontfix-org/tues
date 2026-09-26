//! Driver-independent SFTP types.

use std::time::{Duration, SystemTime};

/// Kind of a remote file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Dir,
    File,
    Symlink,
    Other,
}

impl FileType {
    pub fn is_dir(self) -> bool {
        self == FileType::Dir
    }
    pub fn is_file(self) -> bool {
        self == FileType::File
    }
    pub fn is_symlink(self) -> bool {
        self == FileType::Symlink
    }
}

/// Remote file metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub file_type: FileType,
    pub size: u64,
    /// Full mode bits (type + permissions) if reported.
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub accessed: Option<SystemTime>,
    pub modified: Option<SystemTime>,
}

impl Metadata {
    pub fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }
    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type.is_symlink()
    }
    pub fn len(&self) -> u64 {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    /// Permission bits (lower 12 bits of the mode).
    pub fn permissions(&self) -> Option<u32> {
        self.mode.map(|m| m & 0o7777)
    }

    pub fn from_unix_time(t: Option<u32>) -> Option<SystemTime> {
        t.map(|s| SystemTime::UNIX_EPOCH + Duration::from_secs(s as u64))
    }
}

/// One entry of a remote directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub file_name: String,
    pub metadata: Metadata,
}

impl DirEntry {
    pub fn file_type(&self) -> FileType {
        self.metadata.file_type
    }
}

/// Open flags, modelled after [`std::fs::OpenOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub create: bool,
    pub truncate: bool,
    pub create_new: bool,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(mut self, yes: bool) -> Self {
        self.read = yes;
        self
    }
    pub fn write(mut self, yes: bool) -> Self {
        self.write = yes;
        self
    }
    pub fn append(mut self, yes: bool) -> Self {
        self.append = yes;
        self
    }
    pub fn create(mut self, yes: bool) -> Self {
        self.create = yes;
        self
    }
    pub fn truncate(mut self, yes: bool) -> Self {
        self.truncate = yes;
        self
    }
    pub fn create_new(mut self, yes: bool) -> Self {
        self.create_new = yes;
        self
    }
}
