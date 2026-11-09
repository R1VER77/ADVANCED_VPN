//! Linux-only, bounded TUN adapter. Interface/routing configuration is external.
use anyhow::{Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
};
use tokio::io::unix::AsyncFd;

/// An open TUN device, polled asynchronously.
pub struct Tun(AsyncFd<File>);
impl Tun {
    /// Open the existing TUN device `name` (multi-queue off, no packet info).
    pub fn open(name: &str) -> Result<Self> {
        ensure!(
            !name.is_empty()
                && name.len() < libc::IFNAMSIZ
                && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid TUN name"
        );
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        // SAFETY: an all-zero ifreq is valid before filling its name and flags.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        // SAFETY: fd is open, req is a properly sized initialized Linux ifreq.
        let ret = unsafe { libc::ioctl(f.as_raw_fd(), 0x400454ca as libc::c_ulong, &mut req) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Self::register(f)
    }
    fn register(f: File) -> Result<Self> {
        // SAFETY: File owns a stable open FD for the entire AsyncFd lifetime. It is never replaced or closed through a borrowed reference.
        Ok(Self(unsafe { AsyncFd::register(f) }?))
    }
    /// Use a TUN descriptor inherited from the supervisor, checking it is the device `name`.
    pub fn inherited(fd: i32, name: &str) -> Result<Self> {
        ensure!(fd >= 3, "invalid TUN descriptor");
        // SAFETY: fcntl duplicates an integer FD without pointer arguments.
        let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(n >= 0, "missing TUN descriptor");
        // SAFETY: n is a new owned descriptor from successful fcntl.
        let f = unsafe { File::from_raw_fd(n) };
        // SAFETY: zero initializes the complete ioctl output buffer.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        // SAFETY: TUNGETIFF writes into the initialized ifreq for this owned FD.
        let r = unsafe { libc::ioctl(f.as_raw_fd(), 0x800454d2 as libc::c_ulong, &mut req) };
        ensure!(r >= 0, "inherited descriptor is not a TUN");
        let got: Vec<u8> = req
            .ifr_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        // SAFETY: TUNGETIFF initialized the flag union member.
        let flags = unsafe { req.ifr_ifru.ifru_flags } as i32;
        ensure!(
            got == name.as_bytes() && flags & libc::IFF_TUN != 0 && flags & libc::IFF_NO_PI != 0,
            "wrong inherited TUN"
        );
        // SAFETY: fcntl reads flags on a valid owned descriptor (no pointer arguments).
        let flags = unsafe { libc::fcntl(n, libc::F_GETFL) };
        ensure!(flags >= 0, "cannot read TUN descriptor flags");
        // SAFETY: fcntl sets flags on the same valid owned descriptor.
        let r = unsafe { libc::fcntl(n, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        ensure!(r >= 0, "cannot make TUN nonblocking");
        Self::register(f)
    }
    /// Read one packet into `b`.
    pub async fn read(&self, b: &mut [u8]) -> Result<usize> {
        loop {
            let mut r = self.0.readable().await?;
            match r.try_io(|f| f.get_ref().read(b)) {
                Ok(v) => return Ok(v?),
                Err(_) => continue,
            }
        }
    }
    /// Write one packet.
    pub async fn write(&self, b: &[u8]) -> Result<()> {
        loop {
            let mut r = self.0.writable().await?;
            match r.try_io(|f| f.get_ref().write(b)) {
                Ok(v) => {
                    ensure!(v? == b.len(), "short TUN write");
                    return Ok(());
                }
                Err(_) => continue,
            }
        }
    }
}

/// Whether `b` is a well-formed IPv4 packet from `src` to `dst` no larger than `mtu`.
pub fn valid_ipv4(b: &[u8], src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, mtu: usize) -> bool {
    b.len() >= 20
        && b.len() <= mtu
        && b[0] >> 4 == 4
        && (b[0] & 15) >= 5
        && ((b[0] & 15) as usize) * 4 <= b.len()
        && u16::from_be_bytes([b[2], b[3]]) as usize == b.len()
        && b[12..16] == src.octets()
        && b[16..20] == dst.octets()
}

/// Parse an IPv4 CIDR into (network, mask), refusing host bits.
pub fn network(s: &str) -> Result<(u32, u32)> {
    let (a, b) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR required"))?;
    let a: std::net::Ipv4Addr = a.parse()?;
    let prefix: u32 = b.parse()?;
    ensure!(prefix <= 32, "invalid prefix");
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    ensure!(u32::from(a) & mask == u32::from(a), "network has host bits");
    Ok((u32::from(a), mask))
}
/// Whether a packet may cross: one end must be `fixed` and the other inside `routes`.
pub fn allowed_packet(
    b: &[u8],
    fixed: std::net::Ipv4Addr,
    routes: &[(u32, u32)],
    fixed_source: bool,
    mtu: usize,
) -> bool {
    if b.len() < 20 {
        return false;
    }
    let src = std::net::Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = std::net::Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    if !valid_ipv4(b, src, dst, mtu) {
        return false;
    }
    let (one, other) = if fixed_source { (src, dst) } else { (dst, src) };
    one == fixed
        && routes
            .iter()
            .any(|&(net, mask)| u32::from(other) & mask == net)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_admission_checks_length_addresses_and_version() {
        let a: std::net::Ipv4Addr = "10.77.0.1".parse().unwrap();
        let b: std::net::Ipv4Addr = "10.77.0.2".parse().unwrap();
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[3] = 20;
        p[12..16].copy_from_slice(&a.octets());
        p[16..20].copy_from_slice(&b.octets());
        assert!(valid_ipv4(&p, a, b, 1280));
        assert!(!valid_ipv4(&p, b, a, 1280));
        p[3] = 21;
        assert!(!valid_ipv4(&p, a, b, 1280));
        p[3] = 20;
        p[0] = 0x65;
        assert!(!valid_ipv4(&p, a, b, 1280));
    }
    #[test]
    fn destination_allowlist_and_spoof_rejection() {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[3] = 20;
        p[12..16].copy_from_slice(&[10, 77, 0, 2]);
        p[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let src = "10.77.0.2".parse().unwrap();
        let routes = [network("192.0.2.0/24").unwrap()];
        assert!(allowed_packet(&p, src, &routes, true, 1280));
        p[12] = 11;
        assert!(!allowed_packet(&p, src, &routes, true, 1280));
        assert!(network("192.0.2.1/24").is_err());
        assert!(network("0.0.0.0/33").is_err());
    }
}
