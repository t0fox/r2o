//! C/Rust differential: `probes_word` — русское склонение после числа.

use r2o_controller::classify::probes_word;

fn main() {
    for n in 0..=130 {
        println!("{n} {}", probes_word(n));
    }
}
