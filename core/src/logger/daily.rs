// SPDX-License-Identifier: MIT
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use time::{Date, OffsetDateTime};

// Includes the current log. Rotation follows UTC, as tracing-appender did.
const MAX_LOG_FILES: usize = 30;
const DATE_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");

pub(super) struct DailyFileWriter {
    directory: PathBuf,
    name: String,
    pruned: bool,
}

impl DailyFileWriter {
    pub(super) fn new(directory: &str, key: &str) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        Ok(Self {
            directory: directory.into(),
            name: format!("{key}.log"),
            pruned: false,
        })
    }

    fn write_locked(&mut self, bytes: &[u8], today: Date) -> io::Result<usize> {
        let current = self.directory.join(&self.name);
        // Adopt today's dated log from the previous implementation on upgrade.
        let dated = self.directory.join(format!("{}.{today}", self.name));
        if !current.try_exists()? && dated.try_exists()? {
            fs::rename(dated, &current)?;
        }
        match fs::metadata(&current) {
            Ok(metadata) => {
                let date = OffsetDateTime::from(metadata.modified()?).date();
                if date != today {
                    self.archive(&current, date)?;
                    self.pruned = false;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new().create(true).append(true).open(current)?;
        file.write_all(bytes)?;
        if !self.pruned {
            self.prune()?;
            self.pruned = true;
        }
        Ok(bytes.len())
    }

    fn archive(&self, current: &Path, date: Date) -> io::Result<()> {
        let archive = self.directory.join(format!("{}.{date}", self.name));
        if archive.try_exists()? {
            // A previous version or another run may have written this archive.
            // Append rather than replacing existing records.
            let mut target = OpenOptions::new().append(true).open(archive)?;
            io::copy(&mut File::open(current)?, &mut target)?;
            fs::remove_file(current)
        } else {
            fs::rename(current, archive)
        }
    }

    fn prune(&self) -> io::Result<()> {
        let prefix = format!("{}.", self.name);
        let mut archives = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(date) = name.to_str().and_then(|name| name.strip_prefix(&prefix)) else {
                continue;
            };
            if let Ok(date) = Date::parse(date, DATE_FORMAT) {
                archives.push((date, entry.path()));
            }
        }
        archives.sort_by_key(|(date, _)| *date);
        let excess = archives.len().saturating_sub(MAX_LOG_FILES - 1);
        for (_, path) in archives.into_iter().take(excess) {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

impl Write for DailyFileWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Edge and supernode may share a directory. Reopen the current file
        // under a process-shared lock so neither keeps writing an archive.
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.directory.join(format!(".{}.lock", self.name)))?;
        lock.lock()?;
        // Closing the lock file releases the lock, including on error.
        self.write_locked(bytes, OffsetDateTime::now_utc().date())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vault-daily-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn current_name_and_same_day_restart() {
        let dir = directory();
        DailyFileWriter::new(dir.to_str().unwrap(), "default")
            .unwrap()
            .write_all(b"first\n")
            .unwrap();
        DailyFileWriter::new(dir.to_str().unwrap(), "default")
            .unwrap()
            .write_all(b"second\n")
            .unwrap();
        assert_eq!(
            fs::read(dir.join("default.log")).unwrap(),
            b"first\nsecond\n"
        );
        let today = OffsetDateTime::now_utc().date();
        assert!(!dir.join(format!("default.log.{today}")).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stale_current_is_archived_without_replacing_existing_records() {
        let dir = directory();
        let yesterday = OffsetDateTime::now_utc() - time::Duration::days(1);
        let archive = dir.join(format!("default.log.{}", yesterday.date()));
        fs::write(&archive, "existing\n").unwrap();
        fs::write(dir.join("default.log"), "previous\n").unwrap();
        File::open(dir.join("default.log"))
            .unwrap()
            .set_modified(yesterday.into())
            .unwrap();

        let mut writer = DailyFileWriter::new(dir.to_str().unwrap(), "default").unwrap();
        writer.write_all(b"new\n").unwrap();
        assert_eq!(fs::read(&archive).unwrap(), b"existing\nprevious\n");
        assert_eq!(fs::read(dir.join("default.log")).unwrap(), b"new\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn adopts_legacy_current_file() {
        let dir = directory();
        let today = OffsetDateTime::now_utc().date();
        let legacy = dir.join(format!("error.log.{today}"));
        fs::write(&legacy, "legacy\n").unwrap();
        DailyFileWriter::new(dir.to_str().unwrap(), "error")
            .unwrap()
            .write_all(b"new\n")
            .unwrap();
        assert!(!legacy.exists());
        assert_eq!(fs::read(dir.join("error.log")).unwrap(), b"legacy\nnew\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_writers_keep_records_during_rotation() {
        let dir = directory();
        let yesterday = OffsetDateTime::now_utc() - time::Duration::days(1);
        fs::write(dir.join("default.log"), "old\n").unwrap();
        File::open(dir.join("default.log"))
            .unwrap()
            .set_modified(yesterday.into())
            .unwrap();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let mut writer =
                        DailyFileWriter::new(dir.to_str().unwrap(), "default").unwrap();
                    for _ in 0..20 {
                        writer.write_all(b"new\n").unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            fs::read(dir.join("default.log")).unwrap(),
            b"new\n".repeat(80)
        );
        assert_eq!(
            fs::read(dir.join(format!("default.log.{}", yesterday.date()))).unwrap(),
            b"old\n"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
