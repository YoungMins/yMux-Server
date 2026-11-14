//! Runtime registry of live connections, pairing windows and notify budgets.
//! All methods are short, synchronous critical sections; sending happens in
//! the caller after the lock is released.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::crypto::{b64u, random_bytes};
use crate::limits::{
    NotifyBudget, PairWindow, Pending, TokenBucket, CMD_BURST, CMD_RATE, MAX_CHALLENGES, SUB_BURST,
    SUB_RATE,
};

/// Per-connection channel capacity. A consumer that lets it fill is dropped.
pub const CHANNEL_CAP: usize = 64;

pub enum Out {
    Text(String),
    Ping,
    Close(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer {
    Sent,
    /// The peer's queue is full; the frame was dropped.
    Full,
    /// The peer's connection is already closing.
    Gone,
}

#[derive(Clone)]
pub struct ConnHandle {
    pub conn: String,
    tx: mpsc::Sender<Out>,
    kill: CancellationToken,
}

impl ConnHandle {
    pub fn new(tx: mpsc::Sender<Out>, kill: CancellationToken) -> ConnHandle {
        ConnHandle {
            conn: b64u(&random_bytes::<8>()),
            tx,
            kill,
        }
    }

    /// Queues a frame; a full or closed channel disconnects the peer. For
    /// frames the peer itself is expected to keep up with (its own replies, a
    /// device's relayed messages).
    pub fn send(&self, text: String) -> bool {
        self.push(Out::Text(text))
    }

    /// Queues a frame on behalf of ANOTHER party: when the queue is full the
    /// frame is dropped and the peer stays connected, so one party cannot
    /// knock another one offline by flooding it.
    pub fn offer(&self, text: String) -> Offer {
        match self.tx.try_send(Out::Text(text)) {
            Ok(()) => Offer::Sent,
            Err(mpsc::error::TrySendError::Full(_)) => Offer::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => Offer::Gone,
        }
    }

    pub fn ping(&self) -> bool {
        self.push(Out::Ping)
    }

    fn push(&self, out: Out) -> bool {
        match self.tx.try_send(out) {
            Ok(()) => true,
            Err(_) => {
                self.kill.cancel();
                false
            }
        }
    }

    /// Asks the writer to send a close frame (best effort).
    pub fn close(&self, code: u16) {
        let _ = self.tx.try_send(Out::Close(code));
    }

    pub fn kill(&self) {
        self.kill.cancel();
    }

    pub async fn killed(&self) {
        self.kill.cancelled().await;
    }
}

struct DeviceEntry {
    desktop_id: String,
    handle: ConnHandle,
}

#[derive(Default)]
struct Inner {
    desktops: HashMap<String, ConnHandle>,
    devices: HashMap<String, DeviceEntry>,
    windows: HashMap<String, PairWindow>,
    budgets: HashMap<String, NotifyBudget>,
    /// Per paired device (kept across reconnects); removed with the device.
    cmd_buckets: HashMap<String, TokenBucket>,
    sub_buckets: HashMap<String, TokenBucket>,
}

#[derive(Default)]
pub struct Hub {
    inner: Mutex<Inner>,
}

impl Hub {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers the desktop's live connection. Returns the replaced one and
    /// the devices currently connected to it.
    pub fn register_desktop(
        &self,
        id: &str,
        h: ConnHandle,
        ready: String,
    ) -> (Option<ConnHandle>, Vec<(String, ConnHandle)>) {
        let mut g = self.lock();
        // Queued under the lock so nothing can be relayed ahead of `ready`.
        h.send(ready);
        let old = g.desktops.insert(id.to_string(), h);
        // Pairing state belongs to a connection: a replacement starts clean.
        g.windows.remove(id);
        let devs = g
            .devices
            .iter()
            .filter(|(_, e)| e.desktop_id == id)
            .map(|(d, e)| (d.clone(), e.handle.clone()))
            .collect();
        (old, devs)
    }

    /// Removes the desktop if `conn` is still its live connection; returns the
    /// devices to tell it went offline.
    pub fn unregister_desktop(&self, id: &str, conn: &str) -> Option<Vec<ConnHandle>> {
        let mut g = self.lock();
        match g.desktops.get(id) {
            Some(h) if h.conn == conn => {}
            _ => return None,
        }
        g.desktops.remove(id);
        g.windows.remove(id);
        Some(
            g.devices
                .values()
                .filter(|e| e.desktop_id == id)
                .map(|e| e.handle.clone())
                .collect(),
        )
    }

    pub fn desktop(&self, id: &str) -> Option<ConnHandle> {
        self.lock().desktops.get(id).cloned()
    }

    /// Registers a device connection; a previous one for the same device is returned.
    pub fn register_device(
        &self,
        device_id: &str,
        desktop_id: &str,
        h: ConnHandle,
        ready: impl FnOnce(bool) -> String,
    ) -> (Option<ConnHandle>, Option<ConnHandle>) {
        let mut g = self.lock();
        // Queued under the lock so nothing can be relayed ahead of `ready`.
        h.send(ready(g.desktops.contains_key(desktop_id)));
        let old = g.devices.insert(
            device_id.to_string(),
            DeviceEntry {
                desktop_id: desktop_id.to_string(),
                handle: h,
            },
        );
        (old.map(|e| e.handle), g.desktops.get(desktop_id).cloned())
    }

    /// Removes the device if `conn` is still current. Some(desktop handle) when it was.
    pub fn unregister_device(&self, device_id: &str, conn: &str) -> Option<Option<ConnHandle>> {
        let mut g = self.lock();
        let desktop_id = match g.devices.get(device_id) {
            Some(e) if e.handle.conn == conn => e.desktop_id.clone(),
            _ => return None,
        };
        g.devices.remove(device_id);
        Some(g.desktops.get(&desktop_id).cloned())
    }

    /// The live connection of one device, only if it belongs to `desktop_id`.
    pub fn device_of(&self, desktop_id: &str, device_id: &str) -> Option<ConnHandle> {
        self.lock()
            .devices
            .get(device_id)
            .filter(|e| e.desktop_id == desktop_id)
            .map(|e| e.handle.clone())
    }

    /// Disconnects a device and forgets its rate state (device_remove).
    pub fn kill_device(&self, device_id: &str) {
        let mut g = self.lock();
        g.cmd_buckets.remove(device_id);
        g.sub_buckets.remove(device_id);
        if let Some(e) = g.devices.get(device_id) {
            e.handle.kill();
        }
    }

    /// One `cmd` frame of an authenticated device: 20 per second, burst 40.
    pub fn cmd_allowed(&self, device_id: &str, now: Instant) -> bool {
        self.lock()
            .cmd_buckets
            .entry(device_id.to_string())
            .or_insert_with(|| TokenBucket::new(CMD_BURST, now))
            .take(CMD_RATE, CMD_BURST, now)
    }

    /// One push (un)subscribe frame: each rewrites the state file.
    pub fn sub_allowed(&self, device_id: &str, now: Instant) -> bool {
        self.lock()
            .sub_buckets
            .entry(device_id.to_string())
            .or_insert_with(|| TokenBucket::new(SUB_BURST, now))
            .take(SUB_RATE, SUB_BURST, now)
    }

    /// Hands a desktop's `pair_challenge` to the pairing socket of `device_id`
    /// in that desktop's open window. False (nothing sent) when there is no
    /// window, no such pending request, or the request already had its three.
    pub fn forward_challenge(&self, desktop_id: &str, device_id: &str, body: &str) -> bool {
        let handle = {
            let mut g = self.lock();
            let Some(p) = g
                .windows
                .get_mut(desktop_id)
                .and_then(|w| w.pending.get_mut(device_id))
            else {
                return false;
            };
            if p.challenges >= MAX_CHALLENGES {
                return false;
            }
            p.challenges += 1;
            p.handle.clone()
        };
        handle.send(serde_json::json!({ "t": "pair_challenge", "body": body }).to_string())
    }

    pub fn open_window(&self, desktop_id: &str, ttl_s: u64, now: Instant) {
        self.lock()
            .windows
            .insert(desktop_id.to_string(), PairWindow::new(now, ttl_s));
    }

    /// Dropping the window drops every pending request, which answers them `ok:false`.
    pub fn close_window(&self, desktop_id: &str) {
        self.lock().windows.remove(desktop_id);
    }

    /// Takes a slot in the desktop's window and records the request.
    pub fn add_pending(
        &self,
        desktop_id: &str,
        device_id: &str,
        p: Pending,
        now: Instant,
    ) -> Result<(), &'static str> {
        let mut g = self.lock();
        let Some(w) = g.windows.get_mut(desktop_id) else {
            return Err("no_pairing");
        };
        if w.pending.contains_key(device_id) || !w.take_slot(now) {
            return Err("no_pairing");
        }
        w.pending.insert(device_id.to_string(), p);
        Ok(())
    }

    pub fn take_pending(&self, desktop_id: &str, device_id: &str) -> Option<Pending> {
        self.lock()
            .windows
            .get_mut(desktop_id)?
            .pending
            .remove(device_id)
    }

    pub fn notify_allowed(&self, desktop_id: &str, now: Instant) -> bool {
        self.lock()
            .budgets
            .entry(desktop_id.to_string())
            .or_default()
            .take(now)
    }

    #[cfg(test)]
    pub fn counts(&self) -> (usize, usize) {
        let g = self.lock();
        (g.desktops.len(), g.devices.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> ConnHandle {
        let (tx, _rx) = mpsc::channel(2);
        ConnHandle::new(tx, CancellationToken::new())
    }

    #[test]
    fn replace_and_stale_unregister() {
        let hub = Hub::default();
        let a = handle();
        let b = handle();
        let (old, devs) = hub.register_desktop("d", a.clone(), "{}".into());
        assert!(old.is_none() && devs.is_empty());
        let (old, _) = hub.register_desktop("d", b.clone(), "{}".into());
        assert_eq!(old.unwrap().conn, a.conn);
        // The replaced connection's cleanup must not remove the new one.
        assert!(hub.unregister_desktop("d", &a.conn).is_none());
        assert!(hub.desktop("d").is_some());
        assert!(hub.unregister_desktop("d", &b.conn).is_some());
        assert!(hub.desktop("d").is_none());
    }

    #[test]
    fn full_channel_kills_the_peer() {
        let (tx, _rx) = mpsc::channel(2);
        let kill = CancellationToken::new();
        let h = ConnHandle::new(tx, kill.clone());
        assert!(h.send("1".into()));
        assert!(h.send("2".into()));
        assert!(!kill.is_cancelled());
        assert!(!h.send("3".into()));
        assert!(kill.is_cancelled());
    }

    #[test]
    fn offer_never_cancels_the_peer() {
        let (tx, _rx) = mpsc::channel(2);
        let kill = CancellationToken::new();
        let h = ConnHandle::new(tx, kill.clone());
        assert_eq!(h.offer("1".into()), Offer::Sent);
        assert_eq!(h.offer("2".into()), Offer::Sent);
        assert_eq!(h.offer("3".into()), Offer::Full);
        assert!(!kill.is_cancelled());
        drop(_rx);
        assert_eq!(h.offer("4".into()), Offer::Gone);
        assert!(!kill.is_cancelled());
    }

    #[test]
    fn device_scoping_and_windows() {
        let hub = Hub::default();
        let d = handle();
        hub.register_device("dev", "desk", d.clone(), |_| "{}".into());
        assert!(hub.device_of("desk", "dev").is_some());
        assert!(hub.device_of("other", "dev").is_none());

        let now = Instant::now();
        let (tx, _rx) = oneshot_pair();
        assert_eq!(
            hub.add_pending(
                "desk",
                "dev",
                Pending {
                    pubkey: "k".into(),
                    name: "n".into(),
                    reply: tx,
                    handle: handle(),
                    challenges: 0,
                },
                now
            ),
            Err("no_pairing")
        );
        hub.open_window("desk", 120, now);
        let (tx, rx) = oneshot_pair();
        assert!(hub
            .add_pending(
                "desk",
                "dev",
                Pending {
                    pubkey: "k".into(),
                    name: "n".into(),
                    reply: tx,
                    handle: handle(),
                    challenges: 0,
                },
                now
            )
            .is_ok());
        hub.close_window("desk");
        // Closing the window drops the sender: the waiting pair socket sees ok:false.
        assert!(rx.blocking_recv().is_err());
    }

    fn oneshot_pair() -> (
        tokio::sync::oneshot::Sender<bool>,
        tokio::sync::oneshot::Receiver<bool>,
    ) {
        tokio::sync::oneshot::channel()
    }
}
