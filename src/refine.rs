//! Uniqueness refinement: alternate cheap propagation with small, local SMT
//! queries until neither can settle anything more.
//!
//! Propagation alone leaves a lot open, and the exact per-target query is
//! hopeless on anything but small circuits — influence is undirected for a
//! satisfiability question, so in a program where each value feeds the next,
//! the cone of any witness is the whole circuit.
//!
//! The way out is that an *over-approximation* is enough to prove uniqueness.
//! Dropping constraints only adds solutions, so a query built from a small
//! neighbourhood of a witness can only ever be easier to satisfy than the real
//! system: if even that comes back `UNSAT`, the witness is unique. `SAT` on it
//! proves nothing and is simply ignored here.
//!
//! Each proof feeds back. A wire proven unique joins the determined set, which
//! cuts the next window shorter, which makes the next query smaller. On Noir
//! output this cascades: every `Field`-to-integer cast is a self-contained
//! five-constraint gadget that a radius-2 window settles at once, and once its
//! outputs are determined the values downstream of it fall to plain
//! propagation.

use acir::native_types::Witness;
use picus_smt::{backends::SolverResult, create_backend, query::UniquenessQuery};

use crate::{
    solver::SolverOptions,
    translate::{AcirPicusModel, field_modulus, target_signal},
};

#[derive(Debug, Default)]
pub(crate) struct RefinementStats {
    /// Wires proven unique by a local query.
    pub(crate) proved: usize,
    /// Local queries issued.
    pub(crate) queries: usize,
}

/// The most constraints a local window may carry before it stops being worth
/// solving. Past this the query is no longer "local" and the exact per-target
/// pass will handle it or give up.
///
/// The cap has to be strict, and not because of the time it would take to
/// decide a bigger window honestly: cvc5 checks its `tlimit` between search
/// steps, and a finite-field Groebner basis computation can run far past it.
/// The per-query timeout is therefore advisory, and the only reliable brake is
/// to never hand it a query that could blow up in the first place.
const MAX_WINDOW_CONSTRAINTS: usize = 64;

/// Grow the model's determined set with everything local queries can prove,
/// within `budget_ms` of wall clock.
///
/// Wires are visited in ACIR order, which is roughly the order the compiler
/// produced them, so a gadget's inputs are usually settled before its outputs.
/// A sweep that proved something is repeated, because a newly determined wire
/// shrinks every later window; a sweep that proved nothing ends the pass.
pub(crate) fn refine(
    model: &mut AcirPicusModel,
    options: &SolverOptions,
    radii: &[usize],
    timeout_ms: u64,
    budget_ms: u64,
    on_proved: &mut dyn FnMut(usize),
) -> RefinementStats {
    let mut stats = RefinementStats::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);

    loop {
        let mut progressed = false;
        for witness in model.undetermined_witnesses() {
            if std::time::Instant::now() >= deadline {
                return stats;
            }
            for &radius in radii {
                let query = model.local_window(witness, radius);
                if query.orig.is_empty() || query.orig.len() > MAX_WINDOW_CONSTRAINTS {
                    continue;
                }
                stats.queries += 1;
                // The parent discards this stream; it is here for running the
                // `refine-circuit` subcommand by hand when a circuit misbehaves.
                eprintln!(
                    "refine: w{} radius {radius}, {} constraint(s)",
                    witness.witness_index(),
                    query.orig.len()
                );
                if !is_unique(model, witness, query, options, timeout_ms) {
                    continue;
                }
                model.mark_determined(target_signal(witness));
                on_proved(target_signal(witness));
                stats.proved += 1;
                progressed = true;
                break;
            }
        }
        if !progressed {
            return stats;
        }
    }
}

fn is_unique(
    model: &AcirPicusModel,
    witness: Witness,
    query: crate::translate::SlicedQuery,
    options: &SolverOptions,
    timeout_ms: u64,
) -> bool {
    let query = UniquenessQuery {
        prime: field_modulus(),
        n_wires: model.n_wires,
        input_indices: model.input_indices.iter().copied().collect(),
        orig_constraints: query.orig,
        alt_constraints: query.alt,
        constants: Vec::new(),
        known_signals: model.fixed_known_signals.iter().copied().collect(),
        target_signal: target_signal(witness),
    };

    let Ok(Some(mut backend)) = create_backend(options.solver, options.theory) else {
        return false;
    };
    // Anything other than a clean `UNSAT` — including a solver error — leaves
    // the wire undetermined, which is the safe direction.
    matches!(backend.solve(&query, timeout_ms), Ok(SolverResult::Unsat))
}
