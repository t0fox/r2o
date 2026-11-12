//! C `core/compose.c:567-636`: временный профиль TCP timestamps вокруг connect.
//!
//! Linux выставляет согласование TCP Timestamp через sysctl сетевого
//! пространства имён. Переключаем его только на время `connect()`, затем
//! возвращаем прежнее значение до ожидания ответа.

use std::io;
use std::net::SocketAddr;

/// C-коды отказа: `BadProfile` — -1/EINVAL, `Profile` — -2, `Connect` — -1/errno.
#[derive(Debug)]
pub enum TcpProfileConnectError {
    BadProfile,
    Profile(io::Error),
    Connect(io::Error),
}

pub(crate) const TCP_TIMESTAMPS_PATH: &str = "/proc/sys/net/ipv4/tcp_timestamps";

/// C `tcp_timestamps_read`: первый байт sysctl обязан быть '0'..'2'.
pub(crate) fn tcp_timestamps_read_from(path: &std::path::Path) -> io::Result<u8> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0_u8; 8];
    let read = file.read(&mut buffer)?;
    if read < 1 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "tcp_timestamps: пустой sysctl",
        ));
    }
    if !(b'0'..=b'2').contains(&buffer[0]) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(buffer[0])
}

/// C `tcp_timestamps_write`: ровно один байт значения.
pub(crate) fn tcp_timestamps_write_to(path: &std::path::Path, value: u8) -> io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    let written = file.write(&[value])?;
    if written != 1 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "tcp_timestamps: sysctl принял не один байт",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn raw_connect(fd: libc::c_int, address: &libc::sockaddr_storage, len: libc::socklen_t) -> i32 {
    unsafe { libc::connect(fd, (address as *const libc::sockaddr_storage).cast(), len) }
}

#[cfg(target_os = "linux")]
static TCP_PROFILE_CONNECT_MU: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

/// C `connect_with_tcp_profile` с явными путями sysctl (для тестов).
#[cfg(target_os = "linux")]
pub(crate) fn connect_with_tcp_profile_at(
    fd: libc::c_int,
    address: &libc::sockaddr_storage,
    address_len: libc::socklen_t,
    timestamps: i8,
    read_path: &std::path::Path,
    write_path: &std::path::Path,
) -> Result<(), TcpProfileConnectError> {
    if !(-1..=1).contains(&timestamps) {
        return Err(TcpProfileConnectError::BadProfile);
    }
    let _lock = TCP_PROFILE_CONNECT_MU
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut previous = 0_u8;
    let mut changed = false;
    if timestamps >= 0 {
        previous = tcp_timestamps_read_from(read_path).map_err(TcpProfileConnectError::Profile)?;
        let wanted = if timestamps == 0 { b'0' } else { b'1' };
        if (timestamps == 0 && previous != b'0') || (timestamps == 1 && previous != b'1') {
            if let Err(error) = tcp_timestamps_write_to(write_path, wanted) {
                let _ = tcp_timestamps_write_to(write_path, previous);
                return Err(TcpProfileConnectError::Profile(error));
            }
            changed = true;
        }
    }

    let rc = raw_connect(fd, address, address_len);
    let connect_error = io::Error::last_os_error();
    if changed {
        // C повторяет восстановление дважды: одиночный сбой не должен
        // оставить роутер с чужим sysctl.
        if let Err(error) = tcp_timestamps_write_to(write_path, previous) {
            let _ = tcp_timestamps_write_to(write_path, previous);
            return Err(TcpProfileConnectError::Profile(error));
        }
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(TcpProfileConnectError::Connect(connect_error))
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_for(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    match address {
        SocketAddr::V4(address) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(address) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// C `connect_with_tcp_profile` для production-пути.
#[cfg(target_os = "linux")]
pub fn connect_with_tcp_profile(
    fd: libc::c_int,
    address: SocketAddr,
    timestamps: i8,
) -> Result<(), TcpProfileConnectError> {
    let (raw, len) = sockaddr_for(address);
    connect_with_tcp_profile_at(
        fd,
        &raw,
        len,
        timestamps,
        std::path::Path::new(TCP_TIMESTAMPS_PATH),
        std::path::Path::new(TCP_TIMESTAMPS_PATH),
    )
}

/// C не-Linux: профиль запрошен — EOPNOTSUPP/-2, иначе обычный connect.
#[cfg(not(target_os = "linux"))]
pub fn connect_with_tcp_profile(
    fd: libc::c_int,
    address: SocketAddr,
    timestamps: i8,
) -> Result<(), TcpProfileConnectError> {
    if timestamps >= 0 {
        return Err(TcpProfileConnectError::Profile(
            io::Error::from_raw_os_error(libc::EOPNOTSUPP),
        ));
    }
    let raw = std::net::TcpStream::connect(address);
    let _ = fd;
    match raw {
        Ok(_) => Ok(()),
        Err(error) => Err(TcpProfileConnectError::Connect(error)),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        TcpProfileConnectError, connect_with_tcp_profile_at, tcp_timestamps_read_from,
        tcp_timestamps_write_to,
    };
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-tcp-profile-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        directory
    }

    fn write_sysctl(path: &std::path::Path, value: &str) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(value.as_bytes()).unwrap();
    }

    fn read_sysctl(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn sockaddr_for(address: std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        match address {
            std::net::SocketAddr::V4(address) => {
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: address.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(address.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::write(
                        (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                        raw,
                    );
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            std::net::SocketAddr::V6(address) => {
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: address.port().to_be(),
                    sin6_flowinfo: address.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: address.ip().octets(),
                    },
                    sin6_scope_id: address.scope_id(),
                };
                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::write(
                        (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                        raw,
                    );
                }
                (
                    storage,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    }

    #[test]
    fn sysctl_read_and_write_match_c_strictness() {
        let directory = temp_dir("sysctl");
        let path = directory.join("tcp_timestamps");
        write_sysctl(&path, "1\n");
        assert_eq!(tcp_timestamps_read_from(&path).unwrap(), b'1');
        write_sysctl(&path, "2\n");
        assert_eq!(tcp_timestamps_read_from(&path).unwrap(), b'2');
        write_sysctl(&path, "3\n");
        assert_eq!(
            tcp_timestamps_read_from(&path).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        write_sysctl(&path, "");
        assert!(tcp_timestamps_read_from(&path).is_err());

        tcp_timestamps_write_to(&path, b'0').unwrap();
        assert_eq!(read_sysctl(&path), "0");
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn profile_changes_and_restores_sysctl_around_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = listener.local_addr().unwrap();
        let (raw, len) = sockaddr_for(destination);

        for (previous, wanted) in [("1", 0_i8), ("0", 1_i8), ("1", 1_i8)] {
            let directory = temp_dir("connect");
            let path = directory.join("tcp_timestamps");
            write_sysctl(&path, previous);
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(fd >= 0);
            let rc = connect_with_tcp_profile_at(fd, &raw, len, wanted, &path, &path);
            unsafe { libc::close(fd) };
            assert!(
                matches!(rc, Ok(())),
                "connect/profile отказал для {previous}->{wanted}: {rc:?}"
            );
            assert_eq!(read_sysctl(&path), previous, "sysctl обязан восстановиться");
            std::fs::remove_dir_all(&directory).unwrap();
        }
        drop(listener);
    }

    #[test]
    fn invalid_profile_and_write_failure_match_c_codes() {
        let (raw, len) = sockaddr_for("127.0.0.1:9".parse().unwrap());
        let directory = temp_dir("invalid");
        let path = directory.join("tcp_timestamps");
        write_sysctl(&path, "1");
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);

        assert!(matches!(
            connect_with_tcp_profile_at(fd, &raw, len, 2, &path, &path),
            Err(TcpProfileConnectError::BadProfile)
        ));
        let missing = directory.join("missing");
        assert!(matches!(
            connect_with_tcp_profile_at(fd, &raw, len, 0, &missing, &path),
            Err(TcpProfileConnectError::Profile(_))
        ));
        unsafe { libc::close(fd) };
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn connect_failure_still_restores_previous_value() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = listener.local_addr().unwrap();
        drop(listener);
        let (raw, len) = sockaddr_for(destination);
        let directory = temp_dir("refused");
        let path = directory.join("tcp_timestamps");
        write_sysctl(&path, "1");
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        let rc = connect_with_tcp_profile_at(fd, &raw, len, 0, &path, &path);
        unsafe { libc::close(fd) };
        assert!(matches!(rc, Err(TcpProfileConnectError::Connect(_))));
        assert_eq!(read_sysctl(&path), "1");
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
