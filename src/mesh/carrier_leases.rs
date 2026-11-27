//! Carrier-side enforcement of leases supplied by an admission supervisor.
//!
//! The supervisor owns the other end of an inherited Unix stream. This code
//! cannot mint credits or authenticate a remote client. The channel has no
//! filesystem listener, and closing it stops the shared carrier.

use anyhow::{Context, Result, ensure};
use gotatun::{
    device::{Device, DeviceTransports, Peer},
    x25519::PublicKey,
};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

const MESSAGE_SIZE: usize = 77;
const MAX_LEASE: Duration = Duration::from_secs(3900);
const CLIENT_CAPACITY: usize = 253;

struct Lease {
    address: Ipv4Addr,
    expiry: u64,
    deadline: Instant,
}

/// A private channel and the carrier peers installed through it.
pub struct CarrierLeases {
    socket: UnixStream,
    subnet_prefix: [u8; 3],
    frame: Zeroizing<[u8; MESSAGE_SIZE]>,
    cursor: usize,
    leases: BTreeMap<[u8; 32], Lease>,
}

impl CarrierLeases {
    /// Duplicate an inherited connected Unix socket for the entry shared subnet (`10.78.0.0/24`).
    pub fn from_fd(fd: RawFd) -> Result<Self> {
        Self::from_fd_for_prefix(fd, [10, 78, 0])
    }

    /// Duplicate an inherited connected Unix socket for a validated shared carrier subnet.
    pub fn from_fd_for_prefix(fd: RawFd, subnet_prefix: [u8; 3]) -> Result<Self> {
        ensure!(
            matches!(subnet_prefix, [10, 78, 0] | [10, 79, 0]),
            "unsupported shared carrier subnet"
        );
        ensure!(fd >= 3, "shared supervisor descriptor must be private");
        // SAFETY: fcntl duplicates the caller's scalar descriptor.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(copy >= 0, "missing shared supervisor descriptor");
        // SAFETY: a successful duplicate gives us ownership of a fresh descriptor.
        let file = unsafe { OwnedFd::from_raw_fd(copy) };
        let mut domain: libc::c_int = 0;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid writable buffers of the reported size and a live descriptor.
        let result = unsafe {
            libc::getsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&raw mut domain).cast(),
                &mut length,
            )
        };
        ensure!(
            result == 0 && domain == libc::AF_UNIX,
            "shared supervisor must use a Unix socket"
        );
        let mut socket_type: libc::c_int = 0;
        // SAFETY: valid writable buffers of the reported size and a live descriptor.
        let result = unsafe {
            libc::getsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&raw mut socket_type).cast(),
                &mut length,
            )
        };
        ensure!(
            result == 0 && socket_type == libc::SOCK_STREAM,
            "shared supervisor must use a stream socket"
        );
        let socket = std::os::unix::net::UnixStream::from(file);
        ensure!(
            socket.peer_addr().is_ok(),
            "unconnected shared supervisor socket"
        );
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: UnixStream::from_std(socket)?,
            subnet_prefix,
            frame: Zeroizing::new([0; MESSAGE_SIZE]),
            cursor: 0,
            leases: BTreeMap::new(),
        })
    }

    /// Read a frame without losing partial data when the carrier services a timer.
    pub async fn read_frame(&mut self) -> Result<()> {
        while self.cursor < MESSAGE_SIZE {
            let received = self.socket.read(&mut self.frame[self.cursor..]).await?;
            ensure!(received > 0, "shared admission supervisor disconnected");
            self.cursor += received;
        }
        Ok(())
    }

    /// Earliest expiry expressed on the monotonic clock.
    pub fn deadline(&self) -> Option<Instant> {
        self.leases.values().map(|lease| lease.deadline).min()
    }

    /// Remove expired peers before servicing another frame or reporting health.
    pub async fn expire<T: DeviceTransports>(&mut self, device: &Device<T>) -> Result<()> {
        let wall = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let monotonic = Instant::now();
        let overdue = self
            .leases
            .iter()
            .filter_map(|(key, lease)| {
                (lease.expiry <= wall || lease.deadline <= monotonic).then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in overdue {
            ensure!(
                device.remove_peer(&PublicKey::from(key)).await?,
                "expired carrier peer vanished"
            );
            self.leases.remove(&key);
        }
        Ok(())
    }

    /// Apply one verified supervisor command and acknowledge only after the device changes.
    pub async fn apply<T: DeviceTransports>(
        &mut self,
        device: &Device<T>,
        configure: impl FnOnce(Peer) -> Peer,
    ) -> Result<()> {
        self.expire(device).await?;
        ensure!(
            self.cursor == MESSAGE_SIZE,
            "incomplete shared supervisor command"
        );
        let command = Zeroizing::new(*self.frame);
        self.frame.zeroize();
        self.cursor = 0;
        let key: [u8; 32] = command[1..33].try_into()?;
        ensure!(key != [0; 32], "empty carrier public key");
        match command[0] {
            1 => {
                let psk = Zeroizing::new(<[u8; 32]>::try_from(&command[33..65])?);
                let address = Ipv4Addr::from(<[u8; 4]>::try_from(&command[65..69])?);
                let expiry = u64::from_be_bytes(command[69..77].try_into()?);
                let clock = SystemTime::now().duration_since(UNIX_EPOCH)?;
                let duration = Duration::from_secs(expiry)
                    .checked_sub(clock)
                    .context("carrier lease expired")?;
                ensure!(
                    duration > Duration::ZERO && duration <= MAX_LEASE,
                    "invalid carrier lease lifetime"
                );
                let [a, b, c, host] = address.octets();
                ensure!(
                    [a, b, c] == self.subnet_prefix && (2..=254).contains(&host),
                    "invalid shared carrier address"
                );
                ensure!(*psk != [0; 32], "shared carrier needs a preshared key");
                ensure!(
                    self.leases.len() < CLIENT_CAPACITY
                        && !self.leases.contains_key(&key)
                        && !self.leases.values().any(|lease| lease.address == address),
                    "carrier key or address is occupied"
                );
                let deadline = Instant::now() + duration;
                let peer = configure(
                    Peer::new(PublicKey::from(key))
                        .with_allowed_ip(format!("{address}/32").parse()?)
                        .with_preshared_key(*psk),
                );
                ensure!(
                    device.add_live_peer(peer).await?,
                    "carrier already has this peer"
                );
                self.leases.insert(
                    key,
                    Lease {
                        address,
                        expiry,
                        deadline,
                    },
                );
            }
            2 => {
                ensure!(
                    command[33..].iter().all(|byte| *byte == 0),
                    "invalid removal frame"
                );
                if self.leases.contains_key(&key) {
                    ensure!(
                        device.remove_peer(&PublicKey::from(key)).await?,
                        "carrier peer vanished"
                    );
                    self.leases.remove(&key);
                }
            }
            _ => anyhow::bail!("unknown shared supervisor command"),
        }
        self.expire(device).await?;
        ensure!(
            command[0] != 1 || self.leases.contains_key(&key),
            "carrier lease expired before installation"
        );
        let ack_limit = Instant::now() + Duration::from_secs(1);
        let ack_deadline = self
            .deadline()
            .map_or(ack_limit, |expiry| expiry.min(ack_limit));
        tokio::time::timeout_at(ack_deadline, self.socket.write_all(&[0]))
            .await
            .context("shared supervisor acknowledgment stalled")??;
        Ok(())
    }
}
