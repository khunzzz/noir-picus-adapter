fn main() {
    if let Err(report) = noir_picus_adapter::run() {
        eprintln!("{report:#}");
        std::process::exit(1);
    }
}
