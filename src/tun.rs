//! Linux TUN device support.
//!
//! Creates and configures a TUN interface and provides async read/write
//! operations for raw IP packets.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

use anyhow::{bail, Context, Result};
use async_channel as mpsc;
use bytes::Bytes;

#[cfg(target_os = "linux")]
const TUN_DEVICE: &str = "/dev/net/tun";

#[cfg(target_os = "linux")]
const IFF_TUN: libc::c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: libc::c_short = 0x1000;

#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x400454ca;

#[cfg(target_os = "linux")]
struct TunFd {
    fd: RawFd,
}

#[cfg(target_os = "linux")]
impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Handle for an async TUN device.
///
/// I/O is handled by dedicated background threads (one reader, one writer)
/// that communicate via bounded async channels.  This eliminates the
/// per-packet `spawn_blocking` overhead of the previous implementation and
/// keeps the hot-path entirely in async channel sends/receives.
#[cfg(target_os = "linux")]
pub struct TunDevice {
    name: String,
    mtu: usize,
    /// Receives raw IP packets read from the TUN fd by the background thread.
    rx: mpsc::Receiver<Bytes>,
    /// Sends raw IP packets to the background thread for writing to the TUN fd.
    tx: mpsc::Sender<Bytes>,
}

/// Channel capacity for TUN reader/writer threads.
/// Large enough to absorb short bursts without blocking the I/O threads.
const TUN_CHANNEL_CAP: usize = 2048;

#[cfg(target_os = "linux")]
impl TunDevice {
    /// Create and configure a TUN device.
    ///
    /// Spawns one background reader thread and one background writer thread so
    /// that `read_packet` / `write_packet` are pure async channel operations.
    pub fn create(
        name: &str,
        addr: Ipv4Addr,
        peer: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: usize,
    ) -> Result<Self> {
        if name.len() >= libc::IFNAMSIZ {
            bail!("tun name '{}' too long", name);
        }
        if addr == peer {
            bail!("tun_ip and tun_peer_ip must be different");
        }

        let fd = open_tun()?;
        let if_name = attach_tun(fd, name)?;

        configure_interface(&if_name, addr, peer, netmask, mtu)
            .context("configure tun interface")?;

        log::info!(
            "tun created name={} addr={} peer={} netmask={} mtu={}",
            if_name,
            addr,
            peer,
            netmask,
            mtu
        );

        // ── Background reader ──────────────────────────────────────────────
        // Duplicates the fd so the reader thread owns its copy independently.
        let read_fd = unsafe { libc::dup(fd) };
        let (pkt_tx, pkt_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) =
            mpsc::bounded(TUN_CHANNEL_CAP);
        let read_mtu = mtu;
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; read_mtu + 128];
                loop {
                    let n = unsafe {
                        libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if n < 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        log::warn!("tun read error: {}", e);
                        break;
                    }
                    let pkt = Bytes::copy_from_slice(&buf[..n as usize]);
                    if pkt_tx.send_blocking(pkt).is_err() {
                        break;
                    }
                }
                unsafe { libc::close(read_fd) };
            })
            .context("spawn tun-read thread")?;

        // ── Background writer ──────────────────────────────────────────────
        let write_fd = unsafe { libc::dup(fd) };
        let (write_tx, write_rx): (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) =
            mpsc::bounded(TUN_CHANNEL_CAP);
        std::thread::Builder::new()
            .name("tun-write".into())
            .spawn(move || {
                while let Ok(data) = write_rx.recv_blocking() {
                    let mut offset = 0;
                    while offset < data.len() {
                        let ptr = unsafe { data.as_ptr().add(offset) } as *const libc::c_void;
                        let n = unsafe { libc::write(write_fd, ptr, data.len() - offset) };
                        if n < 0 {
                            let e = io::Error::last_os_error();
                            if e.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            log::warn!("tun write error: {}", e);
                            break;
                        }
                        offset += n as usize;
                    }
                }
                unsafe { libc::close(write_fd) };
            })
            .context("spawn tun-write thread")?;

        // Close original fd – the dup'd copies are owned by the threads.
        unsafe { libc::close(fd) };

        Ok(Self {
            name: if_name,
            mtu,
            rx: pkt_rx,
            tx: write_tx,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Read a single IP packet from the TUN device.
    ///
    /// Uses a dedicated blocking thread (spawned once on [`TunDevice::create`]) to
    /// avoid per-read `spawn_blocking` scheduling overhead.  The packet is delivered
    /// through an async channel.
    pub async fn read_packet(&self) -> Result<Bytes> {
        self.rx
            .recv()
            .await
            .map_err(|_| anyhow::anyhow!("tun reader thread closed"))
    }

    /// Write a single IP packet to the TUN device.
    ///
    /// Writes are sent through an async channel to a dedicated background thread,
    /// eliminating per-write `spawn_blocking` overhead on the hot path.
    pub async fn write_packet(&self, data: &[u8]) -> Result<()> {
        log::trace!("tun write packet_len={}", data.len());
        self.tx
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(|_| anyhow::anyhow!("tun writer thread closed"))
    }
}

#[cfg(not(target_os = "linux"))]
pub struct TunDevice;

#[cfg(not(target_os = "linux"))]
impl TunDevice {
    pub fn create(
        _name: &str,
        _addr: Ipv4Addr,
        _peer: Ipv4Addr,
        _netmask: Ipv4Addr,
        _mtu: usize,
    ) -> Result<Self> {
        bail!("TUN is supported only on Linux")
    }

    pub fn name(&self) -> &str {
        ""
    }
    pub fn mtu(&self) -> usize {
        0
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        bail!("TUN is supported only on Linux")
    }

    pub async fn write_packet(&self, _data: &[u8]) -> Result<()> {
        bail!("TUN is supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
fn open_tun() -> Result<RawFd> {
    let path = std::ffi::CString::new(TUN_DEVICE).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("open /dev/net/tun failed (CAP_NET_ADMIN required)");
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn attach_tun(fd: RawFd, name: &str) -> Result<String> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;
    ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

    let res = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if res < 0 {
        return Err(io::Error::last_os_error()).context("ioctl(TUNSETIFF) failed");
    }

    let if_name = unsafe { CStr::from_ptr(ifr.ifr_name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok(if_name)
}

#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
fn configure_interface(
    if_name: &str,
    addr: Ipv4Addr,
    peer: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: usize,
) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM) failed");
    }

    let res = (|| {
        set_if_addr(sock, if_name, addr)?;
        set_if_netmask(sock, if_name, netmask)?;
        if let Err(e) = set_if_dstaddr(sock, if_name, peer) {
            log::warn!("SIOCSIFDSTADDR failed for {}: {}", if_name, e);
        }
        set_if_mtu(sock, if_name, mtu)?;
        set_if_up(sock, if_name)?;
        Ok(())
    })();

    unsafe { libc::close(sock) };
    res
}

#[cfg(target_os = "linux")]
fn set_ifr_name(ifr: &mut libc::ifreq, name: &str) -> Result<()> {
    if name.len() >= libc::IFNAMSIZ {
        bail!("interface name '{}' too long", name);
    }
    unsafe {
        ptr::write_bytes(ifr.ifr_name.as_mut_ptr(), 0, libc::IFNAMSIZ);
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name.len(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_if_addr(sock: RawFd, name: &str, addr: Ipv4Addr) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from(addr).to_be(),
    };

    unsafe {
        let dst = &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in;
        *dst = sin;
    }

    ioctl_ifreq(sock, libc::SIOCSIFADDR as libc::c_ulong, &mut ifr).context("SIOCSIFADDR")
}

#[cfg(target_os = "linux")]
fn set_if_netmask(sock: RawFd, name: &str, netmask: Ipv4Addr) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from(netmask).to_be(),
    };

    unsafe {
        let dst = &mut ifr.ifr_ifru.ifru_netmask as *mut _ as *mut libc::sockaddr_in;
        *dst = sin;
    }

    ioctl_ifreq(sock, libc::SIOCSIFNETMASK as libc::c_ulong, &mut ifr).context("SIOCSIFNETMASK")
}

#[cfg(target_os = "linux")]
fn set_if_dstaddr(sock: RawFd, name: &str, dst: Ipv4Addr) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from(dst).to_be(),
    };

    unsafe {
        let out = &mut ifr.ifr_ifru.ifru_dstaddr as *mut _ as *mut libc::sockaddr_in;
        *out = sin;
    }

    ioctl_ifreq(sock, libc::SIOCSIFDSTADDR as libc::c_ulong, &mut ifr).context("SIOCSIFDSTADDR")
}

#[cfg(target_os = "linux")]
fn set_if_mtu(sock: RawFd, name: &str, mtu: usize) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;
    ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;

    ioctl_ifreq(sock, libc::SIOCSIFMTU as libc::c_ulong, &mut ifr).context("SIOCSIFMTU")
}

#[cfg(target_os = "linux")]
fn set_if_up(sock: RawFd, name: &str) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    set_ifr_name(&mut ifr, name)?;

    ioctl_ifreq(sock, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr).context("SIOCGIFFLAGS")?;

    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    let new_flags = flags | (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    ifr.ifr_ifru.ifru_flags = new_flags;

    ioctl_ifreq(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &mut ifr).context("SIOCSIFFLAGS")
}

#[cfg(target_os = "linux")]
fn ioctl_ifreq(sock: RawFd, req: libc::c_ulong, ifr: &mut libc::ifreq) -> Result<()> {
    let res = unsafe { libc::ioctl(sock, req, ifr) };
    if res < 0 {
        Err(io::Error::last_os_error()).context("ioctl failed")
    } else {
        Ok(())
    }
}
