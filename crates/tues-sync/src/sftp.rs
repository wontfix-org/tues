use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use tues_core::{DirEntry, Metadata, OpenOptions, Result};

use crate::Runtime;

/// Blocking SFTP session.
#[derive(Clone)]
pub struct Sftp {
    inner: tues_async::Sftp,
    rt: Arc<Runtime>,
}

impl std::fmt::Debug for Sftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sftp")
    }
}

impl Sftp {
    pub(crate) fn new(inner: tues_async::Sftp, rt: Arc<Runtime>) -> Self {
        Sftp { inner, rt }
    }

    pub fn read(&self, path: impl Into<String>) -> Result<Vec<u8>> {
        self.rt.block_on(self.inner.read(path))
    }

    pub fn read_to_string(&self, path: impl Into<String>) -> Result<String> {
        self.rt.block_on(self.inner.read_to_string(path))
    }

    pub fn write(&self, path: impl Into<String>, data: &[u8]) -> Result<()> {
        self.rt.block_on(self.inner.write(path, data))
    }

    pub fn open(&self, path: impl Into<String>) -> Result<File> {
        let f = self.rt.block_on(self.inner.open(path))?;
        Ok(File {
            inner: f,
            rt: self.rt.clone(),
        })
    }

    pub fn create(&self, path: impl Into<String>) -> Result<File> {
        let f = self.rt.block_on(self.inner.create(path))?;
        Ok(File {
            inner: f,
            rt: self.rt.clone(),
        })
    }

    pub fn open_with(&self, path: impl Into<String>, opts: OpenOptions) -> Result<File> {
        let f = self.rt.block_on(self.inner.open_with(path, opts))?;
        Ok(File {
            inner: f,
            rt: self.rt.clone(),
        })
    }

    pub fn read_dir(&self, path: impl Into<String>) -> Result<Vec<DirEntry>> {
        self.rt.block_on(self.inner.read_dir(path))
    }

    pub fn create_dir(&self, path: impl Into<String>) -> Result<()> {
        self.rt.block_on(self.inner.create_dir(path))
    }

    pub fn remove_file(&self, path: impl Into<String>) -> Result<()> {
        self.rt.block_on(self.inner.remove_file(path))
    }

    pub fn remove_dir(&self, path: impl Into<String>) -> Result<()> {
        self.rt.block_on(self.inner.remove_dir(path))
    }

    pub fn rename(&self, from: impl Into<String>, to: impl Into<String>) -> Result<()> {
        self.rt.block_on(self.inner.rename(from, to))
    }

    pub fn symlink(&self, target: impl Into<String>, link: impl Into<String>) -> Result<()> {
        self.rt.block_on(self.inner.symlink(target, link))
    }

    pub fn read_link(&self, path: impl Into<String>) -> Result<String> {
        self.rt.block_on(self.inner.read_link(path))
    }

    pub fn metadata(&self, path: impl Into<String>) -> Result<Metadata> {
        self.rt.block_on(self.inner.metadata(path))
    }

    pub fn symlink_metadata(&self, path: impl Into<String>) -> Result<Metadata> {
        self.rt.block_on(self.inner.symlink_metadata(path))
    }

    pub fn canonicalize(&self, path: impl Into<String>) -> Result<String> {
        self.rt.block_on(self.inner.canonicalize(path))
    }

    pub fn try_exists(&self, path: impl Into<String>) -> Result<bool> {
        self.rt.block_on(self.inner.try_exists(path))
    }

    pub fn close(&self) -> Result<()> {
        self.rt.block_on(self.inner.close())
    }
}

/// An open remote file with blocking I/O.
pub struct File {
    inner: tues_async::File,
    rt: Arc<Runtime>,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("File")
    }
}

impl File {
    pub fn metadata(&self) -> Result<Metadata> {
        self.rt.block_on(self.inner.metadata())
    }

    pub fn sync_all(&self) -> Result<()> {
        self.rt.block_on(self.inner.sync_all())
    }

    /// Flush pending writes and close the remote handle.
    pub fn close(mut self) -> io::Result<()> {
        self.rt.block_on(self.inner.shutdown())
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.rt.block_on(self.inner.read(buf))
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.rt.block_on(self.inner.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.rt.block_on(self.inner.flush())
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.rt.block_on(self.inner.seek(pos))
    }
}
