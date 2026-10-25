use r2o_datapath::conntrack::R2oConntrackTuple;
use r2o_datapath::proc_nat::{R2oProcNatLookup, lookup};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "run through scripts/r2o-nat-proc-differential.sh"]
fn proc_nat_matches_d2o_c_on_shared_conntrack_vectors() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let oracle = std::env::var_os("D2O_NAT_ORACLE").expect("D2O_NAT_ORACLE is set by script");
    let main_table = manifest.join("tests/fixtures/d2o_nat_conntrack.txt");
    let duplicate_table = manifest.join("tests/fixtures/d2o_nat_conntrack_duplicate.txt");
    let absent_table = std::env::temp_dir().join(format!(
        "r2o-nat-absent-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_file(&absent_table);
    let vectors = include_str!("fixtures/d2o_nat_vectors.tsv");
    let mut compared = 0;

    for line in vectors
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
    {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields.len(), 7, "bad vector: {line}");
        let table = match fields[0] {
            "main" => &main_table,
            "duplicate" => &duplicate_table,
            "absent" => &absent_table,
            other => panic!("unknown fixture {other}"),
        };
        let family: u8 = fields[1].parse().unwrap();
        let protocol: u8 = fields[2].parse().unwrap();
        let (source, destination) = if family == 4 {
            let mut source = [0; 16];
            let mut destination = [0; 16];
            source[..4].copy_from_slice(&fields[3].parse::<Ipv4Addr>().unwrap().octets());
            destination[..4].copy_from_slice(&fields[5].parse::<Ipv4Addr>().unwrap().octets());
            (source, destination)
        } else {
            (
                fields[3].parse::<Ipv6Addr>().unwrap().octets(),
                fields[5].parse::<Ipv6Addr>().unwrap().octets(),
            )
        };
        let tuple = R2oConntrackTuple {
            family,
            protocol,
            source,
            destination,
            source_port: fields[4].parse().unwrap(),
            destination_port: fields[6].parse().unwrap(),
        };
        let rust = format_lookup(lookup(table, &tuple));
        let c = Command::new(&oracle)
            .arg(table)
            .arg(protocol.to_string())
            .arg(family.to_string())
            .arg(fields[3])
            .arg(fields[4])
            .arg(fields[5])
            .arg(fields[6])
            .output()
            .expect("run d2o C oracle");
        assert!(c.status.success(), "C oracle failed for {line}: {:?}", c);
        let c = String::from_utf8(c.stdout).unwrap().trim().to_owned();
        assert_eq!(rust, c, "C/Rust mismatch for vector: {line}");
        compared += 1;
    }

    println!("C/Rust proc NAT matched for {compared} shared vectors");
    assert_eq!(compared, 10);
}

fn format_lookup(result: R2oProcNatLookup) -> String {
    match result {
        R2oProcNatLookup::TableMissing => "1 - 0".to_owned(),
        R2oProcNatLookup::Missing => "-1 - 0".to_owned(),
        R2oProcNatLookup::Found(source) => {
            let address = match source.family {
                4 => Ipv4Addr::new(
                    source.address[0],
                    source.address[1],
                    source.address[2],
                    source.address[3],
                )
                .to_string(),
                6 => Ipv6Addr::from(source.address).to_string(),
                _ => unreachable!(),
            };
            format!("0 {address} {}", source.port)
        }
    }
}
