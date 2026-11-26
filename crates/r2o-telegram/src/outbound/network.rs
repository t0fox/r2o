use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const V4: u8 = 1;
const V6: u8 = 2;
const UNKNOWN: u8 = V4 | V6;

pub(crate) struct NetworkState {
    families: AtomicU8,
    generation: AtomicUsize,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            families: AtomicU8::new(UNKNOWN),
            generation: AtomicUsize::new(0),
        }
    }
}

impl NetworkState {
    pub(super) fn permits(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        let family = match address {
            IpAddr::V4(_) => V4,
            IpAddr::V6(ip) if ip.is_unicast_link_local() => return true,
            IpAddr::V6(_) => V6,
        };
        address.is_loopback() || self.families.load(Ordering::Relaxed) & family != 0
    }

    pub(crate) fn generation(&self) -> usize {
        self.generation.load(Ordering::Relaxed)
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::NetworkEvents;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    pub(crate) struct NetworkEvents(AsyncFd<OwnedFd>);

    impl NetworkEvents {
        pub(crate) fn subscribe(state: &NetworkState) -> io::Result<Self> {
            let socket = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if socket == -1 {
                return Err(io::Error::last_os_error());
            }
            let socket = unsafe { OwnedFd::from_raw_fd(socket) };
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            address.nl_groups = (libc::RTMGRP_LINK
                | libc::RTMGRP_IPV4_IFADDR
                | libc::RTMGRP_IPV6_IFADDR
                | libc::RTMGRP_IPV4_ROUTE
                | libc::RTMGRP_IPV6_ROUTE
                | libc::RTMGRP_IPV4_RULE) as u32;
            if unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&raw const address).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            } == -1
            {
                return Err(io::Error::last_os_error());
            }
            let events = Self(AsyncFd::new(socket)?);
            state.families.store(local_families(), Ordering::Relaxed);
            Ok(events)
        }

        pub(crate) async fn changed(&self, state: &NetworkState) -> io::Result<()> {
            // Only change notifications matter. Truncated datagrams still imply a
            // full refresh and ENOBUFS means the kernel dropped some notifications.
            loop {
                let mut ready = self.0.readable().await?;
                match ready.try_io(|socket| receive(socket.get_ref())) {
                    Ok(result) => {
                        if let Err(error) = result {
                            state.families.store(UNKNOWN, Ordering::Relaxed);
                            return Err(error);
                        }
                        break;
                    }
                    Err(_) => continue,
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            for _ in 0..256 {
                if receive(self.0.get_ref()).is_err() {
                    break;
                }
            }
            state.families.store(local_families(), Ordering::Relaxed);
            state.generation.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn receive(socket: &OwnedFd) -> io::Result<()> {
        let mut byte = 0_u8;
        let count = unsafe { libc::recv(socket.as_raw_fd(), (&raw mut byte).cast(), 1, 0) };
        if count >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOBUFS | libc::EINTR) => Ok(()),
            _ => Err(error),
        }
    }

    fn local_families() -> u8 {
        let mut list = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut list) } != 0 {
            return UNKNOWN;
        }
        let mut families = 0;
        let mut entry = list;
        while let Some(address) = unsafe { entry.as_ref() } {
            if !address.ifa_addr.is_null()
                && address.ifa_flags & libc::IFF_UP as u32 != 0
                && address.ifa_flags & libc::IFF_LOOPBACK as u32 == 0
            {
                match unsafe { (*address.ifa_addr).sa_family as libc::c_int } {
                    libc::AF_INET => families |= V4,
                    libc::AF_INET6 => {
                        let address = unsafe { &*address.ifa_addr.cast::<libc::sockaddr_in6>() };
                        let ip = std::net::Ipv6Addr::from(address.sin6_addr.s6_addr);
                        if !ip.is_unicast_link_local() && !ip.is_unspecified() {
                            families |= V6;
                        }
                    }
                    _ => {}
                }
            }
            entry = address.ifa_next;
        }
        unsafe { libc::freeifaddrs(list) };
        families
    }
}
