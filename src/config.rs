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
    /// Issuing authority certificate (DER) for this layer. On a mesh server this file
    /// holds every member's certificate concatenated, so any member handshakes.
    pub ca: PathBuf,
    /// This side's certificate (DER).
    pub cert: PathBuf,
    /// This side's private key (PKCS#8 DER); unused when the key arrives as a sealed FD.
    pub key: PathBuf,
    /// SHA-256 (hex) of the peer's pinned certificate or SubjectPublicKeyInfo.
    /// Empty on a mesh server, which accepts any pin in `peer_members` instead.
    pub peer_sha256: String,
    /// Name the peer's certificate must carry.
    pub server_name: String,
    #[serde(default)]
    /// What `peer_sha256` covers.
    pub pin_kind: PinKind,
    #[serde(default)]
    /// Mesh servers only: the SPKI pins of admitted members. Exactly one of
    /// `peer_sha256` / `peer_members` is non-empty.
    pub peer_members: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
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
    #[serde(default)]
    /// Mesh servers only: admitted members. Empty on clients and single-chain servers.
    pub members: Vec<Member>,
}
fn two_layers() -> usize {
    2
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// One admitted mesh member, as a server sees it: the pin its layer authenticates,
/// and the per-member routing the session needs.
pub struct Member {
    /// SPKI SHA-256 (hex) of this member's certificate for this server's layer.
    pub pin_sha256: String,
    /// Relays only: the member's chosen next hop (`exit`, or the middle relay's exit).
    pub exit: Option<SocketAddr>,
    /// Exit only: the member's inner tunnel address (10.77.0.x), the source its
    /// packets must carry and the destination its returning traffic is routed by.
    pub peer_ip: Option<String>,
}

/// Whether every pin is a unique lowercase 64-hex SHA-256. The empty string is never valid.
fn valid_pins<'a>(pins: impl IntoIterator<Item = &'a String>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    pins.into_iter().all(|p| {
        p.len() == 64
            && p.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && seen.insert(p.as_str())
    })
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
                !i.server_name.is_empty() && i.server_name.len() <= 253,
                "server name required"
            );
            // Exactly one peer model: a single pinned peer, or a mesh member set.
            ensure!(
                valid_pins([&i.peer_sha256]) ^ !i.peer_members.is_empty(),
                "exactly one of peer_sha256 / peer_members required"
            );
            ensure!(
                i.peer_members.len() <= 256 && valid_pins(&i.peer_members),
                "member pins must be unique lowercase SHA256 hex, at most 256"
            );
            ensure!(
                i.peer_members.is_empty() || i.pin_kind == PinKind::Spki,
                "member pins cover public keys (spki)"
            );
            ensure!(
                i.peer_members.is_empty() || self.role != "client",
                "a client pins its one chain; member sets are server-only"
            );
        }
        // Member routing: unique pins, matching the serving layer's accepted set.
        if !self.members.is_empty() {
            ensure!(self.role != "client", "member routing is server-only");
            let (_, identity, _) = self.server_layer()?;
            let accepted: std::collections::BTreeSet<&str> =
                identity.peer_members.iter().map(String::as_str).collect();
            ensure!(
                self.members.len() <= 256
                    && valid_pins(self.members.iter().map(|m| &m.pin_sha256))
                    && self
                        .members
                        .iter()
                        .all(|m| accepted.contains(m.pin_sha256.as_str()))
                    && accepted.len() == self.members.len(),
                "member pins must be unique and exactly the serving layer's accepted set"
            );
            for m in &self.members {
                match self.role.as_str() {
                    "relay" => {
                        let a = m.exit.context("relay member needs its next hop")?;
                        ensure!(
                            a.is_ipv4()
                                && !a.ip().is_unspecified()
                                && !a.ip().is_multicast()
                                && a.port() != 0,
                            "member next hop must be a concrete IPv4 endpoint"
                        );
                        ensure!(m.peer_ip.is_none(), "relays assign no tunnel addresses");
                    }
                    "exit" => {
                        let a: std::net::Ipv4Addr = m
                            .peer_ip
                            .as_deref()
                            .context("exit member needs a tunnel address")?
                            .parse()?;
                        let local: std::net::Ipv4Addr = self
                            .local_ip
                            .as_deref()
                            .context("local_ip required")?
                            .parse()?;
                        ensure!(
                            a.is_private() && a != local,
                            "member tunnel addresses must be private and distinct from the exit's"
                        );
                        ensure!(m.exit.is_none(), "an exit has no next hop");
                    }
                    _ => bail!("unknown role"),
                }
            }
            ensure!(
                self.members
                    .iter()
                    .filter_map(|m| m.peer_ip.as_deref())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == self.members.iter().filter(|m| m.peer_ip.is_some()).count(),
                "member tunnel addresses must be unique"
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
    /// The admitted mesh member whose pin for this server's layer is `pin`.
    pub fn member(&self, pin: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.pin_sha256 == pin)
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

/// The contents of an inherited key descriptor, which must be an immutable sealed memfd
/// of at most `max` bytes. The caller's descriptor is duplicated, never taken over.
pub fn sealed_fd(fd: i32, max: u64) -> Result<Vec<u8>> {
    use std::os::{fd::FromRawFd, unix::fs::FileExt};
    // SAFETY: fcntl F_DUPFD_CLOEXEC duplicates an integer descriptor without pointers.
    let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    ensure!(n >= 0, "invalid inherited key descriptor");
    // SAFETY: n is a newly allocated owned descriptor from successful fcntl.
    let f = unsafe { std::fs::File::from_raw_fd(n) };
    // SAFETY: F_GET_SEALS reads flags on a valid descriptor without pointers.
    let seals = unsafe { libc::fcntl(n, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    ensure!(
        seals >= 0 && seals & required == required,
        "key descriptor must be an immutable sealed memfd"
    );
    let len = f.metadata()?.len();
    ensure!(len <= max, "inherited key too large");
    let mut b = vec![0; len as usize];
    f.read_exact_at(&mut b, 0)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(byte: u8) -> String {
        format!("{:064x}", byte as u64 * 0x0101010101010101)
    }
    fn identity(peer: &str, members: Vec<String>) -> Identity {
        Identity {
            ca: PathBuf::from("/tmp/ca.der"),
            cert: PathBuf::from("/tmp/cert.der"),
            key: PathBuf::from("/tmp/key.der"),
            peer_sha256: peer.into(),
            server_name: "x.advanced-vpn.internal".into(),
            pin_kind: PinKind::Spki,
            peer_members: members,
        }
    }
    fn relay(members: Vec<Member>, accepted: Vec<String>) -> Config {
        Config {
            schema: 1,
            role: "relay".into(),
            listen: "10.78.0.1:4433".parse().unwrap(),
            relay: None,
            exit: Some("203.0.113.80:4444".parse().unwrap()),
            outer: Some(identity("", accepted)),
            middle: None,
            inner: None,
            tun: None,
            local_ip: None,
            peer_ip: None,
            destinations: vec![],
            session_seconds: 300,
            packets_per_second: 1000,
            bytes_per_second: 100_000,
            mtu: 1100,
            layers: 2,
            cells: true,
            members,
        }
    }
    fn relay_member(byte: u8) -> Member {
        Member {
            pin_sha256: pin(byte),
            exit: Some("203.0.113.80:4444".parse().unwrap()),
            peer_ip: None,
        }
    }
    fn exit_member(byte: u8, ip: &str) -> Member {
        Member {
            pin_sha256: pin(byte),
            exit: None,
            peer_ip: Some(ip.into()),
        }
    }

    #[test]
    fn a_mesh_relay_with_consistent_members_is_valid() {
        let c = relay(vec![relay_member(1), relay_member(2)], vec![pin(1), pin(2)]);
        c.validate().unwrap();
        assert_eq!(c.member(&pin(2)).unwrap().pin_sha256, pin(2));
        assert!(c.member(&pin(3)).is_none());
    }
    #[test]
    fn exactly_one_peer_model_is_required() {
        // Both a single pin and a member set is refused.
        let mut c = relay(vec![relay_member(1)], vec![pin(1)]);
        c.outer.as_mut().unwrap().peer_sha256 = pin(1);
        assert!(c.validate().is_err());
        // And so is neither.
        let c = relay(vec![], vec![]);
        assert!(c.validate().is_err());
        // Duplicate member pins are refused.
        let c = relay(vec![relay_member(1), relay_member(1)], vec![pin(1)]);
        assert!(c.validate().is_err());
        // A member the layer does not accept is refused.
        let c = relay(vec![relay_member(1), relay_member(2)], vec![pin(1)]);
        assert!(c.validate().is_err());
    }
    #[test]
    fn member_routing_matches_the_server_role() {
        // A relay member without a next hop is refused.
        let mut m = relay_member(1);
        m.exit = None;
        assert!(relay(vec![m], vec![pin(1)]).validate().is_err());
        // An exit member carries a tunnel address, never a next hop.
        let mut c = relay(vec![exit_member(1, "10.77.0.2")], vec![pin(1)]);
        c.role = "exit".into();
        c.outer = None;
        c.inner = Some(identity("", vec![pin(1)]));
        c.exit = None;
        c.tun = Some("avpn0".into());
        c.local_ip = Some("10.77.0.1".into());
        c.peer_ip = Some("10.77.0.2".into());
        c.destinations = vec!["0.0.0.0/0".into()];
        c.validate().unwrap();
        // Two members may not share a tunnel address.
        c.members = vec![exit_member(1, "10.77.0.2"), exit_member(2, "10.77.0.2")];
        c.inner = Some(identity("", vec![pin(1), pin(2)]));
        assert!(c.validate().is_err());
        // A member may not take the exit's own address.
        c.members = vec![exit_member(1, "10.77.0.1")];
        c.inner = Some(identity("", vec![pin(1)]));
        assert!(c.validate().is_err());
        // A relay member with a tunnel address is refused.
        let mut m = relay_member(1);
        m.peer_ip = Some("10.77.0.9".into());
        assert!(relay(vec![m], vec![pin(1)]).validate().is_err());
    }
    #[test]
    fn a_client_never_carries_a_member_set() {
        let mut c = relay(vec![], vec![]);
        c.role = "client".into();
        c.relay = Some("198.51.100.80:443".parse().unwrap());
        c.outer = Some(identity(&pin(9), vec![pin(1)]));
        c.inner = Some(identity(&pin(8), vec![]));
        c.exit = None;
        c.tun = Some("avpn0".into());
        c.local_ip = Some("10.77.0.2".into());
        c.peer_ip = Some("10.77.0.1".into());
        assert!(c.validate().is_err());
    }
}
