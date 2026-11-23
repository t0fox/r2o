use super::*;

pub(super) fn validate_bundle_abi(bundle: &Path, abi: &str) -> Result<(), InstallError> {
    for component in MANAGER_COMPONENTS.iter().chain(AUXILIARY_COMPONENTS.iter()) {
        let path = bundle
            .join("builds")
            .join(format!("{component}-linux-{abi}"));
        if AUXILIARY_COMPONENTS.contains(component) && !path.try_exists()? {
            continue;
        }
        check_elf(&mut File::open(&path)?, abi).map_err(|error| {
            InstallError::InvalidArchive(format!("{}: {error}", path.display()))
        })?;
    }
    Ok(())
}

fn check_elf(file: &mut File, abi: &str) -> io::Result<()> {
    let (bits, endian, machine, loader): (u8, u8, u16, Option<&[u8]>) = match abi {
        "mipsel" => (1, 1, 8, None),
        "mipsel-openwrt-musl" => (1, 1, 8, Some(b"/lib/ld-musl-mipsel-sf.so.1\0")),
        "aarch64-openwrt-musl" => (2, 1, 183, None),
        "armv5-musleabi" | "armv7-openwrt-musl" | "armv7-musleabi" => (1, 1, 40, None),
        "mips-openwrt-musl" => (1, 2, 8, None),
        "mips64el-musl" => (2, 1, 8, None),
        "x86_64-musl" => (2, 1, 62, None),
        "i686-musl" => (1, 1, 3, None),
        "powerpc64-musl" => (2, 2, 21, None),
        "riscv64-musl" => (2, 1, 243, None),
        _ => return Err(io::Error::other("неподдерживаемый ABI")),
    };
    let mismatch = || io::Error::other("ELF не соответствует ABI выпуска");
    let mut header = [0u8; 64];
    let header_size = if bits == 1 { 52 } else { 64 };
    file.read_exact(&mut header[..header_size])?;
    if &header[..4] != b"\x7fELF" || header[4] != bits || header[5] != endian || header[6] != 1 {
        return Err(mismatch());
    }
    let decode = |bytes: &[u8]| {
        let mut word = [0; 8];
        if endian == 1 {
            word[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(word)
        } else {
            word[8 - bytes.len()..].copy_from_slice(bytes);
            u64::from_be_bytes(word)
        }
    };
    if decode(&header[18..20]) != u64::from(machine) {
        return Err(mismatch());
    }
    let flags = if bits == 1 {
        decode(&header[36..40])
    } else {
        decode(&header[48..52])
    };
    let flags_ok = match abi {
        "mipsel" | "mipsel-openwrt-musl" | "mips-openwrt-musl" => {
            flags & 0xf000_0000 == 0x7000_0000
        }
        "mips64el-musl" => flags & 0xf000_0000 == 0x8000_0000,
        "armv7-openwrt-musl" => flags & 0x400 != 0,
        "armv5-musleabi" | "armv7-musleabi" => flags & 0xff00_0400 == 0x0500_0000,
        "powerpc64-musl" => flags & 0x3 == 2,
        "riscv64-musl" => flags & 0x6 == 4,
        _ => true,
    };
    if !flags_ok {
        return Err(mismatch());
    }
    let (start, size, count) = if bits == 1 {
        (
            decode(&header[28..32]),
            decode(&header[42..44]),
            decode(&header[44..46]),
        )
    } else {
        (
            decode(&header[32..40]),
            decode(&header[54..56]),
            decode(&header[56..58]),
        )
    };
    let expected_size = if bits == 1 { 32 } else { 56 };
    let len = file.metadata()?.len();
    if size != expected_size
        || !(1..=128).contains(&count)
        || start < header_size as u64
        || start.checked_add(size * count).is_none_or(|end| end > len)
    {
        return Err(mismatch());
    }
    let mut matched_loader = false;
    for i in 0..count {
        let mut ph = [0; 56];
        file.seek(SeekFrom::Start(start + i * size))?;
        file.read_exact(&mut ph[..size as usize])?;
        if decode(&ph[..4]) != 3 {
            continue;
        }
        let expected = loader.filter(|_| !matched_loader).ok_or_else(mismatch)?;
        let (offset, length) = if bits == 1 {
            (decode(&ph[4..8]), decode(&ph[16..20]))
        } else {
            (decode(&ph[8..16]), decode(&ph[32..40]))
        };
        if length != expected.len() as u64 || offset.checked_add(length).is_none_or(|end| end > len)
        {
            return Err(mismatch());
        }
        let mut name = [0u8; 64];
        let name = &mut name[..expected.len()];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(name)?;
        if name != expected {
            return Err(mismatch());
        }
        matched_loader = true;
    }
    if matched_loader != loader.is_some() {
        return Err(mismatch());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keenetic_requires_static_mips32r2() {
        let path = std::env::temp_dir().join(format!("r2o-keenetic-abi-{}", std::process::id()));
        let mut bytes = [0u8; 100];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        bytes[18..20].copy_from_slice(&8u16.to_le_bytes());
        bytes[28..32].copy_from_slice(&52u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&0x7000_0000u32.to_le_bytes());
        bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
        bytes[44..46].copy_from_slice(&1u16.to_le_bytes());
        bytes[52..56].copy_from_slice(&1u32.to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(check_elf(&mut File::open(&path).unwrap(), "mipsel").is_ok());

        bytes[52..56].copy_from_slice(&3u32.to_le_bytes());
        bytes[56..60].copy_from_slice(&84u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&13u32.to_le_bytes());
        bytes[84..97].copy_from_slice(b"/lib/ld.so.1\0");
        fs::write(&path, bytes).unwrap();
        assert!(check_elf(&mut File::open(&path).unwrap(), "mipsel").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn abi_check_refuses_wrong_machine_and_wrong_loader() {
        let root = std::env::temp_dir().join(format!("r2o-elf-abi-{}", std::process::id()));
        let mut bytes = [0u8; 120];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        fs::write(&root, bytes).unwrap();
        assert!(check_elf(&mut File::open(&root).unwrap(), "x86_64-musl").is_ok());
        assert!(check_elf(&mut File::open(&root).unwrap(), "aarch64-openwrt-musl").is_err());
        bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
        fs::write(&root, bytes).unwrap();
        assert!(check_elf(&mut File::open(&root).unwrap(), "x86_64-musl").is_err());
        fs::remove_file(&root).unwrap();
    }
}
