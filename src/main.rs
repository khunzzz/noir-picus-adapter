fn main() {
    if let Err(report) = noir_picus_acir::run() {
        eprintln!("{report:#}");
        std::process::exit(1);
    }
}
