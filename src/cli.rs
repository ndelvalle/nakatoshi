pub fn prompt() -> clap::Command {
    clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            clap::Arg::new("prefix")
                .index(1)
                .required_unless_present_any(["input-file"])
                .help("Prefix used to match addresses"),
        )
        .arg(
            clap::Arg::new("input-file")
                .short('i')
                .long("input-file")
                .required_unless_present_any(["prefix"])
                .help("File with prefixes to match addresses with"),
        )
        .arg(
            clap::Arg::new("threads")
                .short('t')
                .long("threads")
                // This is not the actual default value, it is here to pretty display
                // the information.
                .default_value("The number of CPUs available on the current system")
                .help("Number of threads to be used"),
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
                .conflicts_with("case-sensitive")
                .short('b')
                .long("bech32")
                .action(clap::ArgAction::SetTrue)
                .help("Use Bech32 addresses. Starting with bc1q (Lowercase address)"),
        )
        .arg(
            clap::Arg::new("uncompressed")
                .short('u')
                .long("uncompressed")
                .action(clap::ArgAction::SetTrue)
                .help("Use uncompressed private an public keys"),
        )
}
