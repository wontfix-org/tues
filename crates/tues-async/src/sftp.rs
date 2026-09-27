use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use tues_core::{DirEntry, Error, FileType, Metadata, OpenOptions, Result};

/// An SFTP session.
#[derive(Clone)]
pub struct Sftp {
    inner: Arc<SftpSession>,
}

impl std::fmt::Debug for Sftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sftp")
    }
}

fn map_err(e: russh_sftp::client::error::Error) -> Error {
    Error::Sftp(e.to_string())
}

pub(crate) fn convert_metadata(m: &russh_sftp::protocol::FileAttributes) -> Metadata {
    let file_type = match m.file_type() {
        russh_sftp::protocol::FileType::Dir => FileType::Dir,
        russh_sftp::protocol::FileType::File => FileType::File,
        russh_sftp::protocol::FileType::Symlink => FileType::Symlink,
        russh_sftp::protocol::FileType::Other => FileType::Other,
    };
    Metadata {
        file_type,
        size: m.size.unwrap_or(0),
        mode: m.permissions,
        uid: m.uid,
        gid: m.gid,
        accessed: Metadata::from_unix_time(m.atime),
        modified: Metadata::from_unix_time(m.mtime),
    }
}

fn open_flags(o: &OpenOptions) -> OpenFlags {
    let mut f = OpenFlags::empty();
    if o.read {
        f |= OpenFlags::READ;
    }
    if o.write || o.append {
        f |= OpenFlags::WRITE;
    }
    if o.append {
        f |= OpenFlags::APPEND;
    }
    if o.create || o.create_new {
        f |= OpenFlags::CREATE;
    }
    if o.truncate {
        f |= OpenFlags::TRUNCATE;
    }
    if o.create_new {
        f |= OpenFlags::EXCLUDE;
    }
    f
}

impl Sftp {
    pub(crate) async fn new<S>(stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let session = SftpSession::new(stream).await.map_err(map_err)?;
        Ok(Sftp {
            inner: Arc::new(session),
        })
    }

    /// Like [`Sftp::new`], but `prefix` is delivered before anything read from
    /// `stream`. Used when the sudo success marker and the first SFTP bytes
    /// arrived in the same channel packet.
    pub(crate) async fn with_prefix<S>(prefix: Vec<u8>, stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if prefix.is_empty() {
            Self::new(stream).await
        } else {
            Self::new(PrefixStream {
                prefix,
                pos: 0,
                inner: stream,
            })
            .await
        }
    }

    /// Read a whole file.
    pub async fn read(&self, path: impl Into<String>) -> Result<Vec<u8>> {
        self.inner.read(path).await.map_err(map_err)
    }

    /// Read a whole file as UTF-8.
    pub async fn read_to_string(&self, path: impl Into<String>) -> Result<String> {
        let bytes = self.read(path).await?;
        String::from_utf8(bytes).map_err(|e| Error::Sftp(format!("invalid utf-8: {e}")))
    }

    /// Create or truncate a file and write `data` (like [`std::fs::write`]).
    pub async fn write(&self, path: impl Into<String>, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut f = self.inner.create(path).await.map_err(map_err)?;
        f.write_all(data).await?;
        f.shutdown().await?;
        Ok(())
    }

    /// Open for reading.
    pub async fn open(&self, path: impl Into<String>) -> Result<File> {
        self.inner.open(path).await.map(File::new).map_err(map_err)
    }

    /// Create (truncate) for writing.
    pub async fn create(&self, path: impl Into<String>) -> Result<File> {
        self.inner
            .create(path)
            .await
            .map(File::new)
            .map_err(map_err)
    }

    /// Open with explicit options.
    pub async fn open_with(&self, path: impl Into<String>, opts: OpenOptions) -> Result<File> {
        self.inner
            .open_with_flags(path, open_flags(&opts))
            .await
            .map(File::new)
            .map_err(map_err)
    }

    pub async fn read_dir(&self, path: impl Into<String>) -> Result<Vec<DirEntry>> {
        let rd = self.inner.read_dir(path).await.map_err(map_err)?;
        Ok(rd
            .map(|e| DirEntry {
                file_name: e.file_name(),
                metadata: convert_metadata(&e.metadata()),
            })
            .collect())
    }

    pub async fn create_dir(&self, path: impl Into<String>) -> Result<()> {
        self.inner.create_dir(path).await.map_err(map_err)
    }

    pub async fn remove_file(&self, path: impl Into<String>) -> Result<()> {
        self.inner.remove_file(path).await.map_err(map_err)
    }

    pub async fn remove_dir(&self, path: impl Into<String>) -> Result<()> {
        self.inner.remove_dir(path).await.map_err(map_err)
    }

    pub async fn rename(&self, from: impl Into<String>, to: impl Into<String>) -> Result<()> {
        self.inner.rename(from, to).await.map_err(map_err)
    }

    /// Create a symlink at `link` pointing to `target`.
    pub async fn symlink(&self, target: impl Into<String>, link: impl Into<String>) -> Result<()> {
        self.inner.symlink(target, link).await.map_err(map_err)
    }

    pub async fn read_link(&self, path: impl Into<String>) -> Result<String> {
        self.inner.read_link(path).await.map_err(map_err)
    }

    pub async fn metadata(&self, path: impl Into<String>) -> Result<Metadata> {
        self.inner
            .metadata(path)
            .await
            .map(|m| convert_metadata(&m))
            .map_err(map_err)
    }

    pub async fn symlink_metadata(&self, path: impl Into<String>) -> Result<Metadata> {
        self.inner
            .symlink_metadata(path)
            .await
            .map(|m| convert_metadata(&m))
            .map_err(map_err)
    }

    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String> {
        self.inner.canonicalize(path).await.map_err(map_err)
    }

    pub async fn try_exists(&self, path: impl Into<String>) -> Result<bool> {
        self.inner.try_exists(path).await.map_err(map_err)
    }

    /// Close the SFTP channel.
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await.map_err(map_err)
    }
}

/// Bytes already pulled off the channel during the sudo handshake, then the channel.
struct PrefixStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.pos);
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// An open remote file implementing tokio's async I/O traits.
pub struct File {
    inner: russh_sftp::client::fs::File,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("File")
    }
}

impl File {
    fn new(inner: russh_sftp::client::fs::File) -> Self {
        File { inner }
    }

    pub async fn metadata(&self) -> Result<Metadata> {
        self.inner
            .metadata()
            .await
            .map(|m| convert_metadata(&m))
            .map_err(map_err)
    }

    pub async fn sync_all(&self) -> Result<()> {
        self.inner.sync_all().await.map_err(map_err)
    }
}

impl AsyncRead for File {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for File {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncSeek for File {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.inner).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.inner).poll_complete(cx)
    }
}
