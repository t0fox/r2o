use classify::{ClassifyOptions, poison_selected, poisons};

fn print_selected(label: &str, options: &ClassifyOptions) {
    println!(
        "{label}|properties={}",
        u8::from(options.only_poison.is_none())
    );
    println!("{label}|raw={}", u8::from(!options.no_raw));
    let mut printed = 0;
    for poison in poisons() {
        if poison_selected(options, &poison.name) {
            println!("{label}|{}", poison.name);
            printed += 1;
        }
    }
    if printed == 0 {
        println!("{label}|empty");
    }
}

fn main() {
    let mut options = ClassifyOptions::default();
    println!("classifier-timeout-ms={}", options.timeout.as_millis());
    print_selected("all", &options);

    options.only_poison = Some("seqovl-1".into());
    print_selected("only", &options);

    options.only_poison = None;
    options.skip_poisons = vec!["seqovl-1".into(), "badsum-x2-g20".into()];
    print_selected("skip", &options);

    options.only_poison = Some("seqovl-1".into());
    print_selected("only-skipped", &options);

    options.only_poison = Some("unknown-poison".into());
    options.skip_poisons.clear();
    print_selected("only-unknown", &options);

    options.only_poison = None;
    options.no_raw = true;
    print_selected("no-raw", &options);
}
