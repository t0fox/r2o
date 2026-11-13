//! Трасса C/Rust differential: список кандидатов HTTP-поиска, stable id,
//! имена исходов. Печатает ровно те же строки, что C-оракул.

use r2o_controller::http_search::{
    R2oHsAnswer, candidate_text, d2k_hs_answer_name, d2k_hs_candidate_count, d2k_hs_candidate_key,
    d2k_stable_id,
};

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    println!("count={}", d2k_hs_candidate_count());
    for index in 0..d2k_hs_candidate_count() {
        println!(
            "candidate {index}={}",
            d2k_hs_candidate_key(index).unwrap_or_default()
        );
    }
    println!(
        "candidate out_of_range={}",
        if d2k_hs_candidate_key(d2k_hs_candidate_count()).is_some() {
            "some"
        } else {
            "null"
        }
    );

    println!("stable split={}", hex(&d2k_stable_id("split")));
    println!("stable disorder={}", hex(&d2k_stable_id("disorder")));
    println!("stable fake-badsum={}", hex(&d2k_stable_id("fake-badsum")));
    println!(
        "stable fake-spec={}",
        hex(&d2k_stable_id("fake:ttl=5+badsum"))
    );

    let plan_id: [u8; 16] = std::array::from_fn(|index| index as u8);
    for key in [
        "split",
        "disorder",
        "fake-badsum",
        "fake-badsum-whole",
        "fake-seqshift",
        "fake:ttl=5+badsum",
        "nope",
    ] {
        match candidate_text(key, Some(&plan_id)) {
            Some(text) => {
                println!("plan {key} rc=0");
                // C-оракул пишет `d2k-plan`; бренд R2O — осознанное отличие.
                print!("{}", text.replacen("r2o-plan", "d2k-plan", 1));
            }
            None => println!("plan {key} rc=-1"),
        }
    }

    let answers = [
        R2oHsAnswer::None,
        R2oHsAnswer::Real,
        R2oHsAnswer::Injected,
        R2oHsAnswer::Early,
        R2oHsAnswer::Garbage,
        R2oHsAnswer::Silent,
        R2oHsAnswer::Reset,
        R2oHsAnswer::Closed,
        R2oHsAnswer::ConnectFail,
        R2oHsAnswer::Decoy,
        R2oHsAnswer::Cut,
        R2oHsAnswer::Unknown,
    ];
    for (index, answer) in answers.iter().enumerate() {
        println!("answer {index}={}", d2k_hs_answer_name(*answer));
    }
}
