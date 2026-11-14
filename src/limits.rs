//! Pure rate-limit and window logic (time is always passed in).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::hub::ConnHandle;

pub const FAIL_LIMIT: usize = 10;
pub const FAIL_WINDOW: Duration = Duration::from_secs(60);
pub const BLOCK_FOR: Duration = Duration::from_secs(60);
const MAX_TRACKED_IPS: usize = 50_000;

/// The unit rate limits are kept per: an IPv4 address, or the /48 of an IPv6
/// address (a site is usually given a whole /48 and a subscriber a /56 or /64,
/// so anything finer would be free to dodge). IPv4-mapped IPv6 counts as the
/// IPv4 address.
pub fn client_prefix(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(a) => IpAddr::V4(a),
        IpAddr::V6(a) => {
            let mut o = a.octets();
            o[6..].fill(0);
            IpAddr::V6(o.into())
        }
    }
}

/// A token bucket: `rate` tokens per second up to `burst`. Time is passed in.
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(burst: f64, now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: burst,
            last: now,
        }
    }

    /// Takes one token; false when the bucket is empty.
    pub fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A device may send 20 `cmd` frames per second, in bursts of up to 40.
pub const CMD_RATE: f64 = 20.0;
pub const CMD_BURST: f64 = 40.0;
/// Push (un)subscribe frames write the state file under the store lock: one a
/// second, in bursts of up to 5.
pub const SUB_RATE: f64 = 1.0;
pub const SUB_BURST: f64 = 5.0;

pub const MAX_UNAUTH: usize = 64;
pub const MAX_UNAUTH_PER_PREFIX: usize = 8;

/// Connections that have not authenticated yet: at most `MAX_UNAUTH` in
/// total and `MAX_UNAUTH_PER_PREFIX` per client prefix.
#[derive(Default)]
pub struct Unauth {
    inner: Mutex<UnauthInner>,
}

#[derive(Default)]
struct UnauthInner {
    total: usize,
    per_prefix: HashMap<IpAddr, usize>,
}

impl Unauth {
    fn lock(&self) -> std::sync::MutexGuard<'_, UnauthInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn total(&self) -> usize {
        self.lock().total
    }

    /// Takes a slot for `prefix` (already a `client_prefix`), or None when full.
    pub fn acquire(self: &Arc<Self>, prefix: IpAddr) -> Option<UnauthGuard> {
        let mut g = self.lock();
        if g.total >= MAX_UNAUTH
            || g.per_prefix.get(&prefix).copied().unwrap_or(0) >= MAX_UNAUTH_PER_PREFIX
        {
            return None;
        }
        g.total += 1;
        *g.per_prefix.entry(prefix).or_default() += 1;
        Some(UnauthGuard {
            owner: self.clone(),
            prefix,
        })
    }
}

/// Holds one unauthenticated slot until dropped.
pub struct UnauthGuard {
    owner: Arc<Unauth>,
    prefix: IpAddr,
}

impl Drop for UnauthGuard {
    fn drop(&mut self) {
        let mut g = self.owner.lock();
        g.total = g.total.saturating_sub(1);
        if let Some(n) = g.per_prefix.get_mut(&self.prefix) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.per_prefix.remove(&self.prefix);
            }
        }
    }
}

/// Failed handshakes per client prefix: 10 per minute, then refused for a minute.
#[derive(Default)]
pub struct HandshakeLimiter {
    ips: HashMap<IpAddr, IpEntry>,
}

#[derive(Default)]
struct IpEntry {
    fails: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl HandshakeLimiter {
    pub fn allowed(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.ips.get_mut(&ip) {
            Some(e) => match e.blocked_until {
                Some(t) if now < t => false,
                Some(_) => {
                    e.blocked_until = None;
                    e.fails.clear();
                    true
                }
                None => true,
            },
            None => true,
        }
    }

    pub fn record_fail(&mut self, ip: IpAddr, now: Instant) {
        if !self.ips.contains_key(&ip) && self.ips.len() >= MAX_TRACKED_IPS {
            self.prune(now);
            if self.ips.len() >= MAX_TRACKED_IPS {
                return;
            }
        }
        let e = self.ips.entry(ip).or_default();
        while let Some(front) = e.fails.front() {
            if now.duration_since(*front) > FAIL_WINDOW {
                e.fails.pop_front();
            } else {
                break;
            }
        }
        e.fails.push_back(now);
        if e.fails.len() >= FAIL_LIMIT {
            e.blocked_until = Some(now + BLOCK_FOR);
        }
    }

    fn prune(&mut self, now: Instant) {
        self.ips.retain(|_, e| {
            e.blocked_until.map(|t| now < t).unwrap_or(false)
                || e.fails
                    .back()
                    .map(|t| now.duration_since(*t) <= FAIL_WINDOW)
                    .unwrap_or(false)
        });
    }
}

pub const NOTIFY_LIMIT: usize = 30;
pub const NOTIFY_WINDOW: Duration = Duration::from_secs(600);

/// 30 notifications per 10 minutes.
#[derive(Default)]
pub struct NotifyBudget {
    sent: VecDeque<Instant>,
}

impl NotifyBudget {
    pub fn take(&mut self, now: Instant) -> bool {
        while let Some(front) = self.sent.front() {
            if now.duration_since(*front) >= NOTIFY_WINDOW {
                self.sent.pop_front();
            } else {
                break;
            }
        }
        if self.sent.len() >= NOTIFY_LIMIT {
            return false;
        }
        self.sent.push_back(now);
        true
    }
}

pub const WINDOW_MAX_TTL_S: u64 = 120;
pub const WINDOW_MAX_REQUESTS: u32 = 5;

/// `pair_challenge` frames the desktop may send for one pairing request.
pub const MAX_CHALLENGES: u8 = 3;
/// Largest `pair_challenge` body (a sealed `pair_check` is under 100 bytes).
pub const MAX_CHALLENGE_BODY: usize = 4 * 1024;

pub struct Pending {
    pub pubkey: String,
    pub name: String,
    pub reply: oneshot::Sender<bool>,
    /// The waiting pairing socket, the target of `pair_challenge`.
    pub handle: ConnHandle,
    pub challenges: u8,
}

/// A pairing window opened by a desktop.
pub struct PairWindow {
    expires: Instant,
    remaining: u32,
    pub pending: HashMap<String, Pending>,
}

impl PairWindow {
    pub fn new(now: Instant, ttl_s: u64) -> PairWindow {
        let ttl = ttl_s.clamp(1, WINDOW_MAX_TTL_S);
        PairWindow {
            expires: now + Duration::from_secs(ttl),
            remaining: WINDOW_MAX_REQUESTS,
            pending: HashMap::new(),
        }
    }

    pub fn active(&self, now: Instant) -> bool {
        now < self.expires && self.remaining > 0
    }

    /// Consumes one request slot; false when the window is over or exhausted.
    pub fn take_slot(&mut self, now: Instant) -> bool {
        if !self.active(now) {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn blocks_after_ten_fails_for_a_minute() {
        let mut l = HandshakeLimiter::default();
        let t0 = Instant::now();
        for i in 0..9 {
            l.record_fail(ip(1), t0 + Duration::from_secs(i));
            assert!(l.allowed(ip(1), t0 + Duration::from_secs(i)));
        }
        l.record_fail(ip(1), t0 + Duration::from_secs(9));
        assert!(!l.allowed(ip(1), t0 + Duration::from_secs(10)));
        assert!(l.allowed(ip(2), t0 + Duration::from_secs(10)));
        assert!(!l.allowed(ip(1), t0 + Duration::from_secs(68)));
        assert!(l.allowed(ip(1), t0 + Duration::from_secs(70)));
        // Counter restarted after the block.
        l.record_fail(ip(1), t0 + Duration::from_secs(71));
        assert!(l.allowed(ip(1), t0 + Duration::from_secs(72)));
    }

    #[test]
    fn prefix_is_v4_address_or_v6_slash_48() {
        let p = |s: &str| client_prefix(s.parse().unwrap());
        assert_eq!(p("203.0.113.9"), "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(p("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), p("2001:db8:1:2::1"));
        // Different /64s of one /48 are one client.
        assert_eq!(p("2001:db8:1:2::1"), p("2001:db8:1:3::1"));
        assert_eq!(p("2001:db8:1:ffff::1"), p("2001:db8:1::"));
        assert_eq!(
            p("2001:db8:1:2::1"),
            "2001:db8:1::".parse::<IpAddr>().unwrap()
        );
        assert_ne!(p("2001:db8:1:2::1"), p("2001:db8:2:2::1"));
        // Mapped addresses are the IPv4 address they carry.
        assert_eq!(p("::ffff:203.0.113.9"), p("203.0.113.9"));
        assert_ne!(p("203.0.113.9"), p("203.0.113.10"));
    }

    #[test]
    fn ipv6_slash_48_shares_one_failure_budget() {
        let mut l = HandshakeLimiter::default();
        let t0 = Instant::now();
        let a = client_prefix("2001:db8:1:2::1".parse().unwrap());
        // Ten failures from ten different /64s of one /48.
        for i in 0..10u16 {
            let ip: IpAddr = format!("2001:db8:1:{:x}::1", i + 1).parse().unwrap();
            assert!(l.allowed(client_prefix(ip), t0));
            l.record_fail(client_prefix(ip), t0);
        }
        assert!(!l.allowed(a, t0));
        assert!(!l.allowed(client_prefix("2001:db8:1:ffff::9".parse().unwrap()), t0));
        // The next /48 and an IPv4 address are unaffected.
        assert!(l.allowed(client_prefix("2001:db8:2:2::1".parse().unwrap()), t0));
        assert!(l.allowed(client_prefix("198.51.100.1".parse().unwrap()), t0));
    }

    #[test]
    fn token_bucket_bursts_then_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(CMD_BURST, t0);
        for i in 0..40 {
            assert!(b.take(CMD_RATE, CMD_BURST, t0), "{i}");
        }
        assert!(!b.take(CMD_RATE, CMD_BURST, t0));
        // 20 per second: after 100 ms two more, no more.
        let t1 = t0 + Duration::from_millis(100);
        assert!(b.take(CMD_RATE, CMD_BURST, t1));
        assert!(b.take(CMD_RATE, CMD_BURST, t1));
        assert!(!b.take(CMD_RATE, CMD_BURST, t1));
        // Idle time never banks more than the burst.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..40 {
            assert!(b.take(CMD_RATE, CMD_BURST, t2));
        }
        assert!(!b.take(CMD_RATE, CMD_BURST, t2));
    }

    #[test]
    fn unauthenticated_caps_total_and_per_prefix() {
        let u = Arc::new(Unauth::default());
        let v4 = |n: u8| client_prefix(IpAddr::from([10, 0, 0, n]));
        let mut held: Vec<_> = (0..MAX_UNAUTH_PER_PREFIX)
            .map(|_| u.acquire(v4(1)).unwrap())
            .collect();
        assert!(u.acquire(v4(1)).is_none(), "ninth from one prefix");
        assert!(u.acquire(v4(2)).is_some(), "another prefix is fine");
        // A whole /48 is one prefix.
        let v6 = |s: &str| client_prefix(s.parse().unwrap());
        let six: Vec<_> = (0..MAX_UNAUTH_PER_PREFIX)
            .map(|i| u.acquire(v6(&format!("2001:db8:0:{i:x}::1"))).unwrap())
            .collect();
        assert!(u.acquire(v6("2001:db8:0:ffff::1")).is_none());
        assert!(u.acquire(v6("2001:db8:1::1")).is_some());
        // The total cap holds across prefixes.
        for n in 10..=250u8 {
            if u.total() >= MAX_UNAUTH {
                break;
            }
            held.push(u.acquire(v4(n)).unwrap());
        }
        assert_eq!(u.total(), MAX_UNAUTH);
        assert!(u.acquire(v4(251)).is_none());
        drop(six);
        drop(held);
        assert_eq!(u.total(), 0, "released slots are returned");
    }

    #[test]
    fn old_fails_age_out() {
        let mut l = HandshakeLimiter::default();
        let t0 = Instant::now();
        for i in 0..9 {
            l.record_fail(ip(1), t0 + Duration::from_secs(i));
        }
        l.record_fail(ip(1), t0 + Duration::from_secs(120));
        assert!(l.allowed(ip(1), t0 + Duration::from_secs(121)));
    }

    #[test]
    fn notify_budget_is_30_per_10_minutes() {
        let mut b = NotifyBudget::default();
        let t0 = Instant::now();
        for i in 0..30 {
            assert!(b.take(t0 + Duration::from_secs(i)), "{i}");
        }
        assert!(!b.take(t0 + Duration::from_secs(31)));
        assert!(!b.take(t0 + Duration::from_secs(599)));
        assert!(b.take(t0 + Duration::from_secs(600)));
    }

    #[test]
    fn window_ttl_and_request_budget() {
        let t0 = Instant::now();
        let mut w = PairWindow::new(t0, 9999);
        assert!(w.active(t0 + Duration::from_secs(119)));
        assert!(!w.active(t0 + Duration::from_secs(120)));
        for _ in 0..5 {
            assert!(w.take_slot(t0));
        }
        assert!(!w.take_slot(t0));
        assert!(!w.active(t0));
        let w0 = PairWindow::new(t0, 0);
        assert!(w0.active(t0));
        assert!(!w0.active(t0 + Duration::from_secs(1)));
    }
}
