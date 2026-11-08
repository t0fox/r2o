//! CL15: Rust trace чистого порта `d2k_compose`.

use r2o_controller::compose_d2o::{D2K_P_NO, D2K_P_YES, D2oComposeProps, compose_plan_texts};

struct Case {
    name: &'static str,
    props: D2oComposeProps,
    modern: bool,
    decoy: Option<&'static str>,
    send_cap: usize,
    cap: usize,
}

fn main() {
    let legacy = r2k_core::control::SHAPE_LEGACY;
    let modern = r2k_core::control::SHAPE_MODERN;
    let cases = [
        Case {
            name: "empty-legacy",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "empty-modern",
            props: D2oComposeProps::default(),
            modern: true,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "empty-unknown",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "empty-no-decoy",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: None,
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "empty-empty-decoy",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some(""),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "overlap-no",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "overlap-yes",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "reorder-no",
            props: D2oComposeProps {
                tolerates_reorder: D2K_P_NO,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "reorder-yes",
            props: D2oComposeProps {
                tolerates_reorder: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "checksum-no",
            props: D2oComposeProps {
                validates_checksum: D2K_P_NO,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "checksum-no-parse-yes",
            props: D2oComposeProps {
                validates_checksum: D2K_P_NO,
                parses_l7: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "duplicates-yes",
            props: D2oComposeProps {
                counts_duplicates: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "parse-yes",
            props: D2oComposeProps {
                parses_l7: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "overlap-reorder-no",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                tolerates_reorder: D2K_P_NO,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "all-mixed",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                tolerates_reorder: D2K_P_NO,
                validates_checksum: D2K_P_NO,
                parses_l7: D2K_P_YES,
                counts_duplicates: D2K_P_YES,
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "duplicates-modern",
            props: D2oComposeProps {
                counts_duplicates: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: true,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "parse-modern",
            props: D2oComposeProps {
                parses_l7: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: true,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "duplicates-no-decoy",
            props: D2oComposeProps {
                counts_duplicates: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: None,
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "parse-no-decoy",
            props: D2oComposeProps {
                parses_l7: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: None,
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "duplicates-empty-decoy",
            props: D2oComposeProps {
                counts_duplicates: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some(""),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "parse-empty-decoy",
            props: D2oComposeProps {
                parses_l7: D2K_P_YES,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some(""),
            send_cap: 0,
            cap: 8,
        },
        Case {
            name: "empty-sendcap-100",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 100,
            cap: 8,
        },
        Case {
            name: "empty-sendcap-120",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 120,
            cap: 8,
        },
        Case {
            name: "empty-sendcap-200",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 200,
            cap: 8,
        },
        Case {
            name: "all-mixed-sendcap-1500",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                tolerates_reorder: D2K_P_NO,
                validates_checksum: D2K_P_NO,
                parses_l7: D2K_P_YES,
                counts_duplicates: D2K_P_YES,
            },
            modern: true,
            decoy: Some("disk.rzd.ru"),
            send_cap: 1500,
            cap: 8,
        },
        Case {
            name: "overlap-cap-1",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 1,
        },
        Case {
            name: "overlap-cap-0",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                ..D2oComposeProps::default()
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 0,
        },
        Case {
            name: "empty-cap-0",
            props: D2oComposeProps::default(),
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 0,
        },
        Case {
            name: "all-mixed-cap-2",
            props: D2oComposeProps {
                tolerates_left_overlap: D2K_P_NO,
                tolerates_reorder: D2K_P_NO,
                validates_checksum: D2K_P_NO,
                parses_l7: D2K_P_YES,
                counts_duplicates: D2K_P_YES,
            },
            modern: false,
            decoy: Some("disk.rzd.ru"),
            send_cap: 0,
            cap: 2,
        },
    ];
    for case in cases {
        let shape = if case.modern { modern } else { legacy };
        let plans = compose_plan_texts(&case.props, shape, case.decoy, case.send_cap, case.cap);
        println!("case {}\nn={}", case.name, plans.len());
        for (index, plan) in plans.iter().enumerate() {
            println!("plan {index}");
            print!("{plan}");
            if !plan.ends_with('\n') {
                println!();
            }
        }
    }
}
