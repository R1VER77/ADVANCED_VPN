use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// One authenticated QUIC layer: this side's certificate and key, and the peer it pins.
pub struct Identity {
    /// Issuing authority certificate (DER) for this layer.
    pub ca: PathBuf,
    /// This side's certificate (DER).
    pub cert: PathBuf,
    /// This side's private key (PKCS#8 DER); unused when the key arrives as a sealed FD.
    pub key: PathBuf,
    /// SHA-256 (hex) of the peer's pinned certificate or SubjectPublicKeyInfo.
    pub peer_sha256: String,
    /// Name the peer's certificate must carry.
    pub server_name: String,
    #[serde(default)]
    /// What `peer_sha256` covers.
    pub pin_kind: PinKind,
}
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
/// What a pin hashes.
pub enum PinKind {
    #[default]
    /// The whole certificate (legacy static profiles).
    Certificate,
    /// The SubjectPublicKeyInfo, so rotated leaves of the same device identity still match.
    Spki,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// A data-plane configuration: one process, one role, its layers and limits.
pub struct Config {
    /// Configuration schema version (1).
    pub schema: u32,
    /// `client`, `relay` or `exit` (a middle relay runs as `relay`).
    pub role: String,
    /// Local UDP address this process binds.
    pub listen: SocketAddr,
    /// Next hop for a client or an entry/middle relay.
    pub relay: Option<SocketAddr>,
    /// The exit, for the client's innermost layer.
    pub exit: Option<SocketAddr>,
    /// Outer (first-hop) QUIC layer.
    pub outer: Option<Identity>,
    /// Middle relay layer (three-hop chains only).
    #[serde(default)]
    pub middle: Option<Identity>,
    /// Inner (exit) QUIC layer.
    pub inner: Option<Identity>,
    /// TUN device name, for the client and the exit.
    pub tun: Option<String>,
    /// This end's tunnel address.
    pub local_ip: Option<String>,
    /// The other end's tunnel address.
    pub peer_ip: Option<String>,
    /// Destination networks (CIDR) the exit forwards to; everything else is dropped.
    pub destinations: Vec<String>,
    /// Session lifetime in seconds before re-handshake (1..300).
    pub session_seconds: u64,
    /// Per-session packet budget per second, each direction.
    pub packets_per_second: u64,
    /// Per-session byte budget per second, each direction.
    pub bytes_per_second: u64,
    /// Inner IP MTU: 1100 (managed) or 1280 (legacy two-layer).
    pub mtu: usize,
    /// Nested QUIC layers in this chain (1-3 hops; legacy profiles are 2).
    #[serde(default = "two_layers")]
    pub layers: usize,
    /// Constant-cell padding, which is always on: every datagram on every hop is padded
    /// to one size so inner packet sizes do not leak (`avpn help threat-model`). There
    /// is no way to turn it off. The field is required and must be `true`, so a profile
    /// signed before padding existed is refused instead of running unpadded, and an
    /// older build that does not pad refuses a new profile instead of mismatching.
    pub cells: bool,
}
fn two_layers() -> usize {
    2
}

/// Read a private file without following a final symlink: regular, owned by this user, mode 0600 or tighter, at most `max` bytes.
pub fn private_read(path: &Path, max: u64) -> Result<Vec<u8>> {
    // Open without following a final symlink; validate the opened inode, not a raced pathname.
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        m.is_file() && m.uid() == uid && m.mode() & 0o077 == 0,
        "private file ownership/permissions rejected"
    );
    ensure!(m.len() <= max, "private file too large");
    let mut b = Vec::new();
    f.take(max + 1).read_to_end(&mut b)?;
    ensure!(b.len() as u64 <= max, "private file too large");
    Ok(b)
}

impl Config {
    /// Load and validate a configuration file (a private file).
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self =
            serde_json::from_slice(&private_read(path, 65536)?).context("invalid configuration")?;
        c.validate()?;
        Ok(c)
    }
    /// Check every field against the supported profiles and limits.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "unsupported schema");
        ensure!(
            (1..=300).contains(&self.session_seconds),
            "session lifetime must be 1..300 seconds"
        );
        ensure!(
            (1..=100_000).contains(&self.packets_per_second),
            "packet rate out of bounds"
        );
        ensure!(
            (4096..=100_000_000).contains(&self.bytes_per_second),
            "byte rate out of bounds"
        );
        ensure!(
            self.cells,
            "constant-cell padding is required; re-sign this chain with a current avpn init"
        );
        let layers = self.layers;
        ensure!(
            (1..=crate::tls::MAX_HOPS).contains(&layers),
            "chains have 1 to 3 hops"
        );
        ensure!(
            self.mtu == crate::tls::MANAGED_IP_MTU || (self.mtu == 1280 && layers == 2),
            "supported inner MTUs are 1100 (managed) and 1280 (legacy two-layer)"
        );
        ensure!(self.listen.is_ipv4(), "IPv4 underlay required in v0.1");
        ensure!(self.destinations.len() <= 32, "destination list too large");
        for route in &self.destinations {
            crate::tun::network(route)?;
        }
        match self.role.as_str() {
            "relay" => {
                // An entry relay holds the outer layer; a middle relay the middle layer.
                ensure!(
                    (self.outer.is_some() ^ self.middle.is_some())
                        && self.inner.is_none()
                        && self.tun.is_none()
                        && self.destinations.is_empty(),
                    "relay must hold exactly one of the outer/middle layers and no TUN or inner routes"
                );
                ensure!(
                    self.middle.is_none() || layers == 3,
                    "a middle relay exists only in three-hop chains"
                );
                ensure!(
                    self.exit.is_some_and(|a| a.is_ipv4()
                        && !a.ip().is_unspecified()
                        && !a.ip().is_multicast()
                        && a.port() != 0),
                    "fixed exit required"
                );
            }
            "client" => {
                ensure!(
                    self.inner.is_some()
                        && (self.middle.is_none() || self.outer.is_some())
                        && self.relay.is_some_and(|a| a.is_ipv4()
                            && !a.ip().is_unspecified()
                            && !a.ip().is_multicast()
                            && a.port() != 0),
                    "client inner identity, ordered layers and first hop required"
                );
                ensure!(
                    self.lanes().len() == layers,
                    "client layer count must match the chain"
                );
                self.validate_tun()?;
            }
            "exit" => {
                ensure!(
                    self.inner.is_some() && self.outer.is_none() && self.middle.is_none(),
                    "exit must have only an inner identity"
                );
                self.validate_tun()?;
            }
            _ => bail!("unknown role"),
        }
        for i in [&self.outer, &self.middle, &self.inner]
            .into_iter()
            .flatten()
        {
            ensure!(
                i.peer_sha256.len() == 64
                    && i.peer_sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "expected lowercase peer certificate SHA256"
            );
            ensure!(
                !i.server_name.is_empty() && i.server_name.len() <= 253,
                "server name required"
            );
        }
        Ok(())
    }
    /// Layers in wire order: outer (first hop), middle, inner (terminates at the exit).
    pub fn lanes(&self) -> Vec<(&'static str, &Identity)> {
        [
            ("outer", &self.outer),
            ("middle", &self.middle),
            ("inner", &self.inner),
        ]
        .into_iter()
        .filter_map(|(n, i)| i.as_ref().map(|i| (n, i)))
        .collect()
    }
    /// Position of a server's own layer in the chain (0 = first hop).
    pub fn server_layer(&self) -> Result<(&'static str, &Identity, usize)> {
        let layers = self.layers;
        match (&self.outer, &self.middle, &self.inner) {
            (Some(i), None, None) => Ok(("outer", i, 0)),
            (None, Some(i), None) => Ok(("middle", i, 1)),
            (None, None, Some(i)) => Ok(("inner", i, layers - 1)),
            _ => bail!("server must hold exactly one layer"),
        }
    }
    fn validate_tun(&self) -> Result<()> {
        let n = self.tun.as_deref().context("TUN required")?;
        ensure!(
            !n.is_empty()
                && n.len() < 16
                && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid TUN name"
        );
        let a: std::net::Ipv4Addr = self
            .local_ip
            .as_deref()
            .context("local_ip required")?
            .parse()?;
        let b: std::net::Ipv4Addr = self
            .peer_ip
            .as_deref()
            .context("peer_ip required")?
            .parse()?;
        ensure!(
            a.is_private() && b.is_private() && a != b,
            "distinct private inner IPv4 addresses required"
        );
        Ok(())
    }
}

/// Parse `--key-fd ROLE=N` arguments into a role -> inherited FD map (roles outer, middle, inner; FD >= 3).
pub fn key_fds(items: &[String]) -> Result<BTreeMap<String, i32>> {
    let mut out = BTreeMap::new();
    for s in items {
        let (role, fd) = s
            .split_once('=')
            .context("key-fd must be outer=N, middle=N or inner=N")?;
        ensure!(
            matches!(role, "outer" | "middle" | "inner"),
            "unknown key role"
        );
        let fd: i32 = fd.parse()?;
        ensure!(
            fd >= 3 && out.insert(role.to_string(), fd).is_none(),
            "duplicate or invalid key descriptor"
        );
    }
    Ok(out)
}
