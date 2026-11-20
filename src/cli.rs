pub fn prompt() -> clap::Command {
    clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            clap::Arg::new("prefix")
                .index(1)
                .required(true)
                .num_args(1..)
                .help("Prefixes used to match addresses, any one of them is a match"),
        )
        .arg(
            clap::Arg::new("threads")
                .short('t')
                .long("threads")
                .value_parser(clap::value_parser!(std::num::NonZeroUsize))
                .help("Number of threads to be used [default: the number of CPUs]"),
        )
        .arg(
            clap::Arg::new("case-sensitive")
                .short('c')
                .long("case-sensitive")
                .action(clap::ArgAction::SetTrue)
                .help("Use case sensitive comparison to match addresses"),
        )
        .arg(
            clap::Arg::new("bech32")
                .short('b')
                .long("bech32")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("uncompressed")
                .help("Use Bech32 addresses. Starting with bc1q (Lowercase address)"),
        )
        .arg(
            clap::Arg::new("taproot")
                .short('r')
                .long("taproot")
                .visible_alias("p2tr")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["bech32", "uncompressed"])
                .help("Use Taproot addresses. Starting with bc1p (Lowercase address)"),
        )
        .arg(
            clap::Arg::new("keep-going")
                .short('k')
                .long("keep-going")
                .action(clap::ArgAction::SetTrue)
                .help("Don't stop at the first match, print every match and keep searching"),
        )
        .arg(
            clap::Arg::new("uncompressed")
                .short('u')
                .long("uncompressed")
                .action(clap::ArgAction::SetTrue)
                .help("Use uncompressed private and public keys"),
        )
}
