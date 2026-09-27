//! Copy, stat, delete and rename through one SFTP channel.

use std::path::Path;

use tokio::io::AsyncWriteExt;

use tues_core::{Error, FileType, Result};

use crate::sftp::Sftp;

pub(crate) async fn upload(sftp: &Sftp, local: &Path, remote: &str) -> Result<()> {
    let mut stack = vec![(local.to_path_buf(), remote.to_string())];
    while let Some((local, remote)) = stack.pop() {
        let meta = tokio::fs::symlink_metadata(&local).await?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            put_symlink(sftp, &local, &remote).await?;
        } else if ft.is_dir() {
            ensure_remote_dir(sftp, &remote).await?;
            let mut rd = tokio::fs::read_dir(&local).await?;
            while let Some(entry) = rd.next_entry().await? {
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| {
                    Error::Sftp(format!(
                        "{}: file name is not utf-8",
                        entry.path().display()
                    ))
                })?;
                stack.push((entry.path(), remote_join(&remote, name)));
            }
        } else if ft.is_file() {
            let mut src = tokio::fs::File::open(&local).await?;
            let mut dst = sftp.create(&remote).await?;
            tokio::io::copy(&mut src, &mut dst).await?;
            dst.shutdown().await?;
        } else {
            return Err(Error::Sftp(format!(
                "{}: not a file, directory or symlink",
                local.display()
            )));
        }
    }
    Ok(())
}

pub(crate) async fn download(sftp: &Sftp, remote: &str, local: &Path) -> Result<()> {
    let mut stack = vec![(remote.to_string(), local.to_path_buf())];
    while let Some((remote, local)) = stack.pop() {
        let md = sftp.symlink_metadata(&remote).await?;
        match md.file_type {
            FileType::Symlink => {
                let target = sftp.read_link(&remote).await?;
                if tokio::fs::symlink_metadata(&local)
                    .await
                    .ok()
                    .filter(|m| m.is_dir())
                    .is_some()
                {
                    return Err(Error::Sftp(format!("{} is a directory", local.display())));
                }
                let _ = tokio::fs::remove_file(&local).await;
                symlink_local(Path::new(&target), &local)?;
            }
            FileType::Dir => {
                tokio::fs::create_dir_all(&local).await?;
                for entry in sftp.read_dir(&remote).await? {
                    if entry.file_name == "." || entry.file_name == ".." {
                        continue;
                    }
                    stack.push((
                        remote_join(&remote, &entry.file_name),
                        local.join(&entry.file_name),
                    ));
                }
            }
            FileType::File | FileType::Other => {
                if let Some(parent) = local.parent()
                    && !parent.as_os_str().is_empty()
                {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let mut src = sftp.open(&remote).await?;
                let mut dst = tokio::fs::File::create(&local).await?;
                tokio::io::copy(&mut src, &mut dst).await?;
                dst.shutdown().await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn delete(sftp: &Sftp, path: &str) -> Result<()> {
    enum Step {
        Visit(String),
        RemoveDir(String),
    }
    let mut stack = vec![Step::Visit(path.to_string())];
    while let Some(step) = stack.pop() {
        match step {
            Step::RemoveDir(path) => sftp.remove_dir(path).await?,
            Step::Visit(path) => {
                let md = sftp.symlink_metadata(&path).await?;
                if md.is_dir() {
                    stack.push(Step::RemoveDir(path.clone()));
                    for entry in sftp.read_dir(&path).await? {
                        if entry.file_name == "." || entry.file_name == ".." {
                            continue;
                        }
                        stack.push(Step::Visit(remote_join(&path, &entry.file_name)));
                    }
                } else {
                    sftp.remove_file(path).await?;
                }
            }
        }
    }
    Ok(())
}

async fn put_symlink(sftp: &Sftp, local: &Path, remote: &str) -> Result<()> {
    let target = tokio::fs::read_link(local).await?;
    let target = target
        .to_str()
        .ok_or_else(|| Error::Sftp(format!("{}: link target is not utf-8", local.display())))?;
    match sftp.symlink_metadata(remote).await {
        Ok(md) if md.is_dir() => {
            return Err(Error::Sftp(format!("{remote} is a directory")));
        }
        Ok(_) => sftp.remove_file(remote).await?,
        Err(_) => {}
    }
    sftp.symlink(target, remote).await
}

async fn ensure_remote_dir(sftp: &Sftp, path: &str) -> Result<()> {
    match sftp.symlink_metadata(path).await {
        Ok(md) if md.is_dir() => Ok(()),
        Ok(_) => Err(Error::Sftp(format!("{path} exists and is not a directory"))),
        Err(_) => sftp.create_dir(path).await,
    }
}

fn remote_join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn symlink_local(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link);
        Err(Error::Sftp(
            "symlinks are not supported on this platform".into(),
        ))
    }
}
