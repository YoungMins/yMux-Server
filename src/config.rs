//! Configuration from environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Protocol timing. Tests shorten these.
#[derive(Clone, Debug)]
pub struct Timing {
    /// Time a client has to answer the challenge.
    pub handshake: Duration,
    /// Server ping period.
    pub ping: Duration,
    /// A connection silent for this long is closed.
    pub idle: Duration,
    /// Time one outgoing frame may take to write before the peer is dropped.
    pub write: Duration,
    /// How long a pair socket waits for the desktop's decision.
    pub pair_wait: Duration,
    /// One overall deadline for a single push delivery, DNS included.
    pub push_deadline: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            handshake: Duration::from_secs(10),
            ping: Duration::from_secs(30),
            idle: Duration::from_secs(75),
            write: Duration::from_secs(10),
            pair_wait: Duration::from_secs(125),
            push_deadline: Duration::from_secs(15),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    /// Origin of the public URL, e.g. `https://remote.example.com`.
    pub origin: String,
    pub https: bool,
    pub data_dir: PathBuf,
    pub trust_proxy: bool,
    pub timing: Timing,
}

/// Validates the public URL and returns its origin and whether it is https.
pub fn parse_public_url(raw: &str) -> Result<(String, bool), String> {
    let url = url::Url::parse(raw.trim())
        .map_err(|e| format!("YMUX_SERVER_PUBLIC_URL is not a URL: {e}"))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "YMUX_SERVER_PUBLIC_URL must not contain credentials, a query or a fragment".into(),
        );
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(
            "YMUX_SERVER_PUBLIC_URL must not contain a path (serve yMux at the root of its host)"
                .into(),
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| "YMUX_SERVER_PUBLIC_URL has no host".to_string())?;
    let https = match url.scheme() {
        "https" => true,
        "http" if host == "localhost" || host == "127.0.0.1" => false,
        "http" => {
            return Err(
                "YMUX_SERVER_PUBLIC_URL must be https:// (http:// is only accepted for localhost / 127.0.0.1)".into(),
            )
        }
        _ => return Err("YMUX_SERVER_PUBLIC_URL must be an https:// URL".into()),
    };
    Ok((url.origin().ascii_serialization(), https))
}

impl Config {
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Config, String> {
        let bind = get("YMUX_SERVER_BIND").unwrap_or_else(|| "127.0.0.1:11020".to_string());
        let bind: SocketAddr = bind
            .trim()
            .parse()
            .map_err(|e| format!("YMUX_SERVER_BIND is not a socket address: {e}"))?;
        let public = get("YMUX_SERVER_PUBLIC_URL")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "YMUX_SERVER_PUBLIC_URL is required (the https:// address users reach this server at)".to_string())?;
        let (origin, https) = parse_public_url(&public)?;
        let data_dir =
            PathBuf::from(get("YMUX_SERVER_DATA_DIR").unwrap_or_else(|| "./data".to_string()));
        let trust_proxy = matches!(
            get("YMUX_SERVER_TRUST_PROXY").as_deref().map(str::trim),
            Some("1")
        );
        Ok(Config {
            bind,
            origin,
            https,
            data_dir,
            trust_proxy,
            timing: Timing::default(),
        })
    }

    pub fn from_env() -> Result<Config, String> {
        Config::from_lookup(&|k| std::env::var(k).ok())
    }
}

/// Data dir only (for the `token` subcommand, which needs no public URL).
pub fn data_dir_from_env() -> PathBuf {
    PathBuf::from(std::env::var("YMUX_SERVER_DATA_DIR").unwrap_or_else(|_| "./data".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(&move |k| owned.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()))
    }

    #[test]
    fn public_url_is_required_and_https() {
        assert!(cfg(&[]).is_err());
        assert!(cfg(&[("YMUX_SERVER_PUBLIC_URL", "http://example.com")]).is_err());
        assert!(cfg(&[("YMUX_SERVER_PUBLIC_URL", "ftp://example.com")]).is_err());
        assert!(cfg(&[("YMUX_SERVER_PUBLIC_URL", "https://example.com/sub")]).is_err());
        assert!(cfg(&[("YMUX_SERVER_PUBLIC_URL", "https://u:p@example.com")]).is_err());
        let c = cfg(&[("YMUX_SERVER_PUBLIC_URL", "https://Example.com/")]).unwrap();
        assert_eq!(c.origin, "https://example.com");
        assert!(c.https);
        assert_eq!(c.bind.to_string(), "127.0.0.1:11020");
        assert!(!c.trust_proxy);
    }

    #[test]
    fn http_only_for_loopback_dev() {
        let c = cfg(&[("YMUX_SERVER_PUBLIC_URL", "http://localhost:11020")]).unwrap();
        assert_eq!(c.origin, "http://localhost:11020");
        assert!(!c.https);
        assert!(cfg(&[("YMUX_SERVER_PUBLIC_URL", "http://127.0.0.1:9")]).is_ok());
        assert!(cfg(&[("YMUX_SERVER_PUBLIC_URL", "http://192.168.1.2")]).is_err());
    }

    #[test]
    fn trust_proxy_and_bind() {
        let c = cfg(&[
            ("YMUX_SERVER_PUBLIC_URL", "https://a.example:8443"),
            ("YMUX_SERVER_TRUST_PROXY", "1"),
            ("YMUX_SERVER_BIND", "0.0.0.0:80"),
        ])
        .unwrap();
        assert!(c.trust_proxy);
        assert_eq!(c.origin, "https://a.example:8443");
        assert!(cfg(&[
            ("YMUX_SERVER_PUBLIC_URL", "https://a.example"),
            ("YMUX_SERVER_BIND", "nope")
        ])
        .is_err());
    }
}
