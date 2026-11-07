//! Печатает таблицу TCP shape contexts для C/Rust differential-теста D20.

use r2k_core::control::{
    r2k_link_shape_tcp_base, r2k_link_shape_tcp_context, r2k_link_shape_tcp_profile,
};

fn main() {
    for shape in 0_u8..=15 {
        print!(
            "{} {} {}",
            shape,
            r2k_link_shape_tcp_profile(shape),
            r2k_link_shape_tcp_base(shape)
        );
        for profile in 0_u8..=3 {
            print!(" {}", r2k_link_shape_tcp_context(shape, profile));
        }
        println!();
    }
}
