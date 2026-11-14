//! Persistent state, two files with one writer each, both replaced atomically:
//!
//! - `state.json`: the VAPID key pair, desktops and devices. Written only by
//!   the running server.
//! - `setup-token`: the setup token. Written only by the `token --rotate`
//!   command (and once at creation); the server only reads it, again on every
//!   unknown-desktop handshake. Neither process can undo the other's write.
//!
//! Relayed `body` content is never stored.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::{b64u, clean_device_name, clean_name, random_bytes};

pub const FILE_NAME: &str = "state.json";
pub const TOKEN_FILE: &str = "setup-token";
pub const MAX_DEVICES_PER_DESKTOP: usize = 16;
pub const MAX_DESKTOPS: usize = 64;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PushSub {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DesktopRec {
    pub pubkey: String,
    pub name: String,
    pub created: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceRec {
    pub desktop_id: String,
    pub pubkey: String,
    pub name: String,
    pub created: u64,
    #[serde(default)]
    pub push: Option<PushSub>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct State {
    pub version: u32,
    /// Only read, to move a token out of a state file written by an older
    /// version into `setup-token`; never written back.
    #[serde(default, rename = "setup_token", skip_serializing)]
    pub legacy_setup_token: String,
    pub vapid_private: String,
    pub vapid_public: String,
    #[serde(default)]
    pub desktops: BTreeMap<String, DesktopRec>,
    #[serde(default)]
    pub devices: BTreeMap<String, DeviceRec>,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn new_token() -> String {
    b64u(&random_bytes::<32>())
}

impl State {
    pub fn fresh() -> State {
        let sk = SecretKey::random(&mut OsRng);
        State {
            version: 1,
            legacy_setup_token: String::new(),
            vapid_private: b64u(&sk.to_bytes()),
            vapid_public: b64u(sk.public_key().to_encoded_point(false).as_bytes()),
            desktops: BTreeMap::new(),
            devices: BTreeMap::new(),
        }
    }

    pub fn devices_of(&self, desktop_id: &str) -> Vec<String> {
        self.devices
            .iter()
            .filter(|(_, d)| d.desktop_id == desktop_id)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

pub fn token_path(dir: &Path) -> PathBuf {
    dir.join(TOKEN_FILE)
}

/// The setup token on disk, or None when the file is missing or unusable.
pub fn read_token(dir: &Path) -> Option<String> {
    // A replace that lands exactly now can make one read fail on Windows.
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if let Ok(t) = fs::read_to_string(token_path(dir)) {
            let t = t.trim();
            return (!t.is_empty() && t.len() <= 256).then(|| t.to_string());
        }
    }
    None
}

/// Returns the setup token, creating the file when it does not exist: from
/// `legacy` (a token found in an old state file) if given, else a new random
/// one. The bool is true only for a brand-new random token. Safe against a
/// concurrent creator: the file appears complete or not at all, and whoever
/// loses the race reads the winner's token.
pub fn ensure_token(dir: &Path, legacy: &str) -> std::io::Result<(String, bool)> {
    fs::create_dir_all(dir)?;
    if let Some(t) = read_token(dir) {
        return Ok((t, false));
    }
    let fresh = legacy.trim().is_empty();
    let token = if fresh {
        new_token()
    } else {
        legacy.trim().to_string()
    };
    if create_new(&token_path(dir), format!("{token}\n").as_bytes())? {
        return Ok((token, fresh));
    }
    match read_token(dir) {
        Some(t) => Ok((t, false)),
        None => Err(std::io::Error::other(format!(
            "{} exists but holds no usable token",
            token_path(dir).display()
        ))),
    }
}

/// Replaces the setup token. Touches only the token file, so it cannot undo
/// or be undone by anything the server writes to the state file.
pub fn rotate_token(dir: &Path) -> std::io::Result<String> {
    fs::create_dir_all(dir)?;
    let token = new_token();
    write_atomic(&token_path(dir), format!("{token}\n").as_bytes())?;
    Ok(token)
}

/// The token for the `token` command: the file, else one migrated from an old
/// state file, else a new one. Never writes the state file.
pub fn token_for_cli(dir: &Path) -> std::io::Result<String> {
    if let Some(t) = read_token(dir) {
        return Ok(t);
    }
    let legacy = fs::read(dir.join(FILE_NAME))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("setup_token")?.as_str().map(str::to_string))
        .unwrap_or_default();
    ensure_token(dir, &legacy).map(|(t, _)| t)
}

pub struct Store {
    dir: PathBuf,
    path: PathBuf,
    pub state: State,
}

impl Store {
    /// Opens (or creates) the state. The bool is true when a new setup token
    /// was generated. A state file that exists but cannot be parsed is an
    /// error, never overwritten.
    pub fn open(dir: &Path) -> Result<(Store, bool), String> {
        fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create data dir {}: {e}", dir.display()))?;
        let path = dir.join(FILE_NAME);
        let mut store = match fs::read(&path) {
            Ok(bytes) => {
                let mut state: State = serde_json::from_slice(&bytes).map_err(|e| {
                    format!(
                        "{} is not valid ({e}); refusing to overwrite it",
                        path.display()
                    )
                })?;
                if state.version != 1 {
                    return Err(format!(
                        "{} has unsupported version {}",
                        path.display(),
                        state.version
                    ));
                }
                // Names are untrusted text; older files may hold unclean ones.
                for d in state.desktops.values_mut() {
                    d.name = clean_name(&d.name);
                }
                for d in state.devices.values_mut() {
                    d.name = clean_device_name(&d.name);
                }
                Store {
                    dir: dir.to_path_buf(),
                    path,
                    state,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let store = Store {
                    dir: dir.to_path_buf(),
                    path,
                    state: State::fresh(),
                };
                store.save().map_err(|e| {
                    format!("cannot write state file {}: {e}", store.path.display())
                })?;
                store
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        // The token lives in its own file. The file is created before the old
        // copy in the state file is dropped, so a crash in between loses nothing.
        let legacy = std::mem::take(&mut store.state.legacy_setup_token);
        let (_, created) = ensure_token(dir, &legacy)
            .map_err(|e| format!("cannot write {}: {e}", token_path(dir).display()))?;
        if !legacy.is_empty() {
            store
                .save()
                .map_err(|e| format!("cannot rewrite {}: {e}", store.path.display()))?;
        }
        Ok((store, created))
    }

    /// The current setup token (the file is the only truth for it, so a
    /// rotation while the server runs takes effect at once). None when the
    /// file is missing or unreadable; callers must then refuse registration.
    pub fn setup_token(&self) -> Option<String> {
        read_token(&self.dir)
    }

    pub fn save(&self) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        write_atomic(&self.path, &bytes)
    }

    /// Persists, logging (never failing the caller) on I/O errors.
    pub fn persist(&mut self) {
        if let Err(e) = self.save() {
            tracing::error!(error = %e, "state write failed");
        }
    }

    pub fn add_desktop(&mut self, id: &str, pubkey: &str, name: &str) {
        self.state.desktops.insert(
            id.to_string(),
            DesktopRec {
                pubkey: pubkey.to_string(),
                name: clean_name(name),
                created: now_secs(),
            },
        );
        self.persist();
    }

    /// Adds or replaces a device. False when the desktop already has the maximum
    /// number of other devices, or the id belongs to a different desktop.
    pub fn add_device(
        &mut self,
        desktop_id: &str,
        device_id: &str,
        pubkey: &str,
        name: &str,
    ) -> bool {
        match self.state.devices.get(device_id) {
            Some(d) if d.desktop_id != desktop_id => return false,
            Some(_) => {}
            None => {
                if self.state.devices_of(desktop_id).len() >= MAX_DEVICES_PER_DESKTOP {
                    return false;
                }
            }
        }
        let push = self
            .state
            .devices
            .get(device_id)
            .and_then(|d| d.push.clone());
        self.state.devices.insert(
            device_id.to_string(),
            DeviceRec {
                desktop_id: desktop_id.to_string(),
                pubkey: pubkey.to_string(),
                name: clean_device_name(name),
                created: now_secs(),
                push,
            },
        );
        self.persist();
        true
    }

    pub fn remove_device(&mut self, desktop_id: &str, device_id: &str) -> bool {
        let owned = self
            .state
            .devices
            .get(device_id)
            .map(|d| d.desktop_id == desktop_id)
            .unwrap_or(false);
        if owned {
            self.state.devices.remove(device_id);
            self.persist();
        }
        owned
    }

    pub fn set_push(&mut self, device_id: &str, sub: Option<PushSub>) {
        if let Some(d) = self.state.devices.get_mut(device_id) {
            if d.push != sub {
                d.push = sub;
                self.persist();
            }
        }
    }

    /// Deletes the subscription only if it is still the one that failed.
    pub fn clear_push_if(&mut self, device_id: &str, endpoint: &str) {
        if let Some(d) = self.state.devices.get_mut(device_id) {
            if d.push
                .as_ref()
                .map(|p| p.endpoint == endpoint)
                .unwrap_or(false)
            {
                d.push = None;
                self.persist();
            }
        }
    }
}

/// Writes `bytes` to a fresh temp file next to `path` (0600 on Unix) and syncs it.
fn write_temp(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
        b64u(&random_bytes::<6>())
    ));
    let result = (|| {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    match result {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn sync_dir(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(Ok(d)) = path.parent().map(fs::File::open) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Temp file in the same directory + fsync + rename; 0600 on Unix.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = write_temp(path, bytes)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(path);
    Ok(())
}

/// Creates `path` with complete content unless it already exists. True when
/// this call created it. The content is written to a temp file first and
/// hard-linked into place, so a reader never sees a half-written file and two
/// creators cannot both win. (A filesystem without hard links falls back to
/// check-then-rename, which only leaves a window between two simultaneous
/// first starts.)
fn create_new(path: &Path, bytes: &[u8]) -> std::io::Result<bool> {
    let tmp = write_temp(path, bytes)?;
    let result = match fs::hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(_) if !path.exists() => fs::rename(&tmp, path).map(|()| true),
        Err(_) => Ok(false),
    };
    let _ = fs::remove_file(&tmp);
    if matches!(result, Ok(true)) {
        sync_dir(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, created) = Store::open(dir.path()).unwrap();
        assert!(created);
        let tok = s.setup_token().unwrap();
        assert_eq!(tok.len(), 43);
        s.add_desktop("d1", "pk", "PC");
        let (s2, created2) = Store::open(dir.path()).unwrap();
        assert!(!created2);
        assert_eq!(s2.setup_token().unwrap(), tok);
        assert!(s2.state.desktops.contains_key("d1"));
        // Exactly the two files; no temp files left behind.
        let mut names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, [TOKEN_FILE, FILE_NAME]);
        // The state file does not hold the token.
        let text = fs::read_to_string(dir.path().join(FILE_NAME)).unwrap();
        assert!(!text.contains(&tok) && !text.contains("setup_token"));
    }

    #[test]
    fn token_moves_out_of_an_old_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut old = serde_json::to_value(State::fresh()).unwrap();
        old["setup_token"] = serde_json::json!("OLDTOKEN");
        fs::write(dir.path().join(FILE_NAME), old.to_string()).unwrap();
        // The CLI alone moves it and leaves the state file untouched.
        assert_eq!(token_for_cli(dir.path()).unwrap(), "OLDTOKEN");
        assert!(fs::read_to_string(dir.path().join(FILE_NAME))
            .unwrap()
            .contains("OLDTOKEN"));
        fs::remove_file(token_path(dir.path())).unwrap();
        // The server migrates and then drops the old copy.
        let (s, created) = Store::open(dir.path()).unwrap();
        assert!(!created, "a migrated token is not a new one");
        assert_eq!(s.setup_token().unwrap(), "OLDTOKEN");
        assert!(!fs::read_to_string(dir.path().join(FILE_NAME))
            .unwrap()
            .contains("OLDTOKEN"));
        // A token file that already exists wins over a stale copy.
        rotate_token(dir.path()).unwrap();
        let (s, _) = Store::open(dir.path()).unwrap();
        assert_ne!(s.setup_token().unwrap(), "OLDTOKEN");
    }

    #[test]
    fn names_are_cleaned_on_store_and_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = Store::open(dir.path()).unwrap();
        s.add_desktop("d", "pk", "My\u{202E}PC\u{200B}");
        assert!(s.add_device("d", "dev", "pk", &format!("a\u{FEFF}{}", "b".repeat(200))));
        assert_eq!(s.state.desktops["d"].name, "MyPC");
        assert_eq!(s.state.devices["dev"].name.chars().count(), 40);
        assert!(s.state.devices["dev"].name.starts_with("ab"));
        assert!(s.add_device("d", "dev2", "pk", "Pixel 8 \u{201C}482913\u{201D}"));
        assert_eq!(s.state.devices["dev2"].name, "Pixel");
        // A file written before the rule existed is cleaned when read.
        s.state.desktops.get_mut("d").unwrap().name = "x\u{202E}y".into();
        s.save().unwrap();
        let (s2, _) = Store::open(dir.path()).unwrap();
        assert_eq!(s2.state.desktops["d"].name, "xy");
    }

    #[cfg(unix)]
    #[test]
    fn file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (_s, _) = Store::open(dir.path()).unwrap();
        for f in [FILE_NAME, TOKEN_FILE] {
            let mode = fs::metadata(dir.path().join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
        rotate_token(dir.path()).unwrap();
        let mode = fs::metadata(token_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_file_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE_NAME), b"{not json").unwrap();
        assert!(Store::open(dir.path()).is_err());
        assert_eq!(fs::read(dir.path().join(FILE_NAME)).unwrap(), b"{not json");
    }

    #[test]
    fn device_limits_and_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = Store::open(dir.path()).unwrap();
        for i in 0..MAX_DEVICES_PER_DESKTOP {
            assert!(s.add_device("a", &format!("dev{i}"), "pk", "n"));
        }
        assert!(!s.add_device("a", "extra", "pk", "n"));
        // Re-pairing an existing device is fine.
        assert!(s.add_device("a", "dev0", "pk2", "n"));
        // Another desktop cannot take the id over.
        assert!(!s.add_device("b", "dev0", "pk3", "n"));
        assert!(!s.remove_device("b", "dev0"));
        assert!(s.remove_device("a", "dev0"));
    }

    #[test]
    fn rotation_survives_a_running_server_save() {
        let dir = tempfile::tempdir().unwrap();
        let (mut running, _) = Store::open(dir.path()).unwrap();
        let new = rotate_token(dir.path()).unwrap();
        running.add_desktop("d", "pk", "n"); // a server save must not touch the token
        assert_eq!(running.setup_token().unwrap(), new);
        let (again, _) = Store::open(dir.path()).unwrap();
        assert_eq!(again.setup_token().unwrap(), new);
        assert!(again.state.desktops.contains_key("d"));
    }

    /// The CLI rotating in a loop while the server keeps registering: no
    /// registration is lost, no rotation is undone, and the token file is
    /// always a complete token.
    #[test]
    fn concurrent_rotation_and_registration_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut running, _) = Store::open(dir.path()).unwrap();
        let path = dir.path().to_path_buf();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (stop2, path2) = (stop.clone(), path.clone());
        let rotator = std::thread::spawn(move || {
            let mut last = String::new();
            while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
                last = rotate_token(&path2).unwrap();
            }
            last
        });
        for i in 0..60 {
            running.add_desktop(&format!("d{i}"), "pk", "n");
            let seen = read_token(&path).expect("token file is always complete");
            assert_eq!(seen.len(), 43);
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let last = rotator.join().unwrap();
        assert_eq!(read_token(&path).unwrap(), last, "the last rotation stands");
        let (again, _) = Store::open(&path).unwrap();
        assert_eq!(again.state.desktops.len(), 60, "no registration lost");
    }

    #[test]
    fn two_first_starts_agree_on_one_token() {
        let dir = tempfile::tempdir().unwrap();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = dir.path().to_path_buf();
                std::thread::spawn(move || ensure_token(&p, "").unwrap())
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, created)| *created).count(), 1);
        assert!(results.iter().all(|(t, _)| *t == results[0].0));
        assert_eq!(read_token(dir.path()).unwrap(), results[0].0);
    }

    #[test]
    fn clear_push_only_when_endpoint_matches() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = Store::open(dir.path()).unwrap();
        s.add_device("a", "dev", "pk", "n");
        let sub = PushSub {
            endpoint: "https://x/1".into(),
            p256dh: "k".into(),
            auth: "a".into(),
        };
        s.set_push("dev", Some(sub));
        s.clear_push_if("dev", "https://x/other");
        assert!(s.state.devices["dev"].push.is_some());
        s.clear_push_if("dev", "https://x/1");
        assert!(s.state.devices["dev"].push.is_none());
    }
}
