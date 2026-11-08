use r2o_controller::classify::{DpiProps, TriState, Trigger};

fn main() {
    let trigger = Trigger::tls("target.example").unwrap();
    let cases = [
        ("empty", DpiProps::default()),
        (
            "overlap-no",
            DpiProps {
                tolerates_left_overlap: TriState::False,
                ..DpiProps::default()
            },
        ),
        (
            "overlap-yes",
            DpiProps {
                tolerates_left_overlap: TriState::True,
                ..DpiProps::default()
            },
        ),
        (
            "reorder-no",
            DpiProps {
                tolerates_reorder: TriState::False,
                ..DpiProps::default()
            },
        ),
        (
            "reorder-yes",
            DpiProps {
                tolerates_reorder: TriState::True,
                ..DpiProps::default()
            },
        ),
        (
            "checksum-no",
            DpiProps {
                validates_checksum: TriState::False,
                ..DpiProps::default()
            },
        ),
        (
            "checksum-no-parse-yes",
            DpiProps {
                validates_checksum: TriState::False,
                parses_l7: TriState::True,
                ..DpiProps::default()
            },
        ),
        (
            "duplicates-yes",
            DpiProps {
                counts_duplicates: TriState::True,
                ..DpiProps::default()
            },
        ),
        (
            "parse-yes",
            DpiProps {
                parses_l7: TriState::True,
                ..DpiProps::default()
            },
        ),
        (
            "overlap-reorder-no",
            DpiProps {
                tolerates_left_overlap: TriState::False,
                tolerates_reorder: TriState::False,
                ..DpiProps::default()
            },
        ),
        (
            "all-mixed",
            DpiProps {
                tolerates_left_overlap: TriState::False,
                tolerates_reorder: TriState::False,
                validates_checksum: TriState::False,
                parses_l7: TriState::True,
                counts_duplicates: TriState::True,
                ..DpiProps::default()
            },
        ),
    ];
    for (name, props) in cases {
        let plans = r2o_controller::ask::compose_plan_texts(
            &props,
            &trigger,
            r2k_core::control::SHAPE_LEGACY,
            Some("disk.rzd.ru"),
            0,
        )
        .unwrap_or_default();
        println!("case {name}");
        println!("n={}", plans.len());
        for plan in plans {
            let body = plan.split_once('\n').map(|(_, body)| body).unwrap_or("");
            println!("plan");
            print!("{body}");
            if !body.ends_with('\n') {
                println!();
            }
        }
    }
}
