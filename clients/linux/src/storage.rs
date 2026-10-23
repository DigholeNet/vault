// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct SimpleFileStorage {
    path: PathBuf,
}

impl SimpleFileStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        Ok(Self {
            path: path.as_ref().to_path_buf(),
        })
    }

    pub fn store<S: AsRef<str>, D: AsRef<str>>(&self, key: S, data: D) -> anyhow::Result<()> {
        // A corrupt file is an error, not an empty map: merging into a
        // default map and rewriting would silently drop the stored device id
        // (and with it the server's IP lease).
        let mut kv = match fs::read_to_string(&self.path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| {
                anyhow::anyhow!("corrupt storage file {}: {}", self.path.display(), e)
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };

        let key = key.as_ref().to_string();
        let value = data.as_ref().to_string();

        kv.insert(key, value);

        let s = serde_json::to_string_pretty(&kv)?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write-then-rename keeps the last good file intact if the process
        // dies mid-write; a truncated JSON would otherwise lose the device id.
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, s)?;
        fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }

    pub fn get<S: AsRef<str>>(&self, key: S) -> anyhow::Result<Option<String>> {
        if !fs::exists(&self.path)? {
            return Ok(None);
        }
        let key = key.as_ref();
        let s = fs::read_to_string(&self.path)?;
        let kv: HashMap<String, String> = serde_json::from_str(&s)?;

        Ok(kv.get(key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("edge-test-{}-{}", std::process::id(), name))
    }

    #[test]
    fn missing_file_returns_none() {
        let storage = SimpleFileStorage::new(temp_path("missing")).unwrap();
        assert_eq!(storage.get("id").unwrap(), None);
    }

    #[test]
    fn store_and_get_roundtrip() {
        let path = temp_path("roundtrip");
        let storage = SimpleFileStorage::new(&path).unwrap();

        storage.store("id", "abcdef").unwrap();
        assert_eq!(storage.get("id").unwrap().as_deref(), Some("abcdef"));
        assert_eq!(storage.get("other").unwrap(), None);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn overwrite_preserves_other_keys() {
        let path = temp_path("overwrite");
        let storage = SimpleFileStorage::new(&path).unwrap();

        storage.store("a", "1").unwrap();
        storage.store("b", "2").unwrap();
        storage.store("a", "3").unwrap();

        assert_eq!(storage.get("a").unwrap().as_deref(), Some("3"));
        assert_eq!(storage.get("b").unwrap().as_deref(), Some("2"));

        fs::remove_file(&path).ok();
    }

    #[test]
    fn store_creates_parents() {
        let path = temp_path("nested").join("a/b/storage.dat");
        let storage = SimpleFileStorage::new(&path).unwrap();

        storage.store("id", "xyz").unwrap();
        assert_eq!(storage.get("id").unwrap().as_deref(), Some("xyz"));

        fs::remove_dir_all(temp_path("nested")).ok();
    }
}
