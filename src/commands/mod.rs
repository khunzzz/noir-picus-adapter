//! One module per subcommand. Each exposes a function taking its parsed
//! arguments; `lib.rs` only dispatches.

pub(crate) mod fuzz;
pub(crate) mod mutate;
pub(crate) mod scan;
pub(crate) mod unpinned;
pub(crate) mod witness;
