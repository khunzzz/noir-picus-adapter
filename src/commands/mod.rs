//! One module per subcommand. Each exposes a function taking its parsed
//! arguments; `lib.rs` only dispatches.

pub(crate) mod fuzz;
pub(crate) mod mutants;
pub(crate) mod mutate;
pub(crate) mod scan;
pub(crate) mod unpinned;
pub(crate) mod witness;

/// For the hidden child subcommands: exit as soon as the parent is gone.
///
/// A parent kills its child on its own deadline, but a parent that is itself
/// killed (by a benchmark harness's timeout, or Ctrl-C) cannot. cvc5 ignores
/// its own time limit inside a Gröbner basis computation, so an orphaned
/// child would otherwise run indefinitely, holding a core. Reparenting is how
/// the child finds out.
pub(crate) fn exit_with_parent() {
    #[cfg(unix)]
    {
        let parent = std::os::unix::process::parent_id();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if std::os::unix::process::parent_id() != parent {
                    std::process::exit(124);
                }
            }
        });
    }
}
