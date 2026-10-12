//! The local-window query, sent to cvc5 directly rather than through the
//! Picus backend.
//!
//! The Picus backend is built for whole-circuit queries: it declares both
//! copies of every wire in the circuit and asserts `x = y` for every determined
//! wire, then asks for a model on `SAT`. For a window of a few dozen
//! constraints in a 50 000-witness circuit that is ~100 000 declarations, ~1000
//! equalities and, on the usual `SAT`, ~100 000 `get-value` calls — per query.
//! It also leaves cvc5 on its default finite-field engine, a single traced
//! Gröbner basis, which on Noir's bit-decomposition windows runs far past its
//! time limit (`tlimit` is only checked between search steps).
//!
//! Here only the wires the window mentions are declared, only their
//! determined-wire equalities are asserted, and no model is requested. The
//! window goes first to cvc5's split Gröbner engine (`ff-solver=split`), which
//! rejects the usual satisfiable window far faster; an `UNSAT` from it is only
//! accepted once the default engine agrees (see `is_unique`: the split engine
//! is not sound in cvc5 1.3.1).
//!
//! Neither engine honours its time limit reliably: the split engine recurses
//! through fresh Gröbner bases, each with its own budget. So every query runs
//! in a child process (the hidden `solve-window` subcommand) that is killed on
//! a hard deadline. Spawning costs a few milliseconds; one runaway window
//! would otherwise cost the whole refinement budget.

use std::collections::{BTreeSet, HashMap};

use num_bigint::BigUint;
use picus_smt::query::{IRConstraint, IRProductTerm, IRTerm};
use serde::{Deserialize, Serialize};

/// Everything a window query needs. Variable names follow `var_name`: `x{n}`
/// for the first copy and for shared wires, `y{n}` for the second copy.
pub(super) struct Window<'a> {
    pub(super) prime: &'a BigUint,
    pub(super) orig: &'a [IRConstraint],
    pub(super) alt: &'a [IRConstraint],
    pub(super) known: &'a BTreeSet<usize>,
    pub(super) target: usize,
}

/// Solve `window` in a child process with a hard deadline. `true` only on a
/// clean `UNSAT`; a `SAT`, a give-up, a crash and a kill all leave the wire
/// undetermined, which is the safe direction.
pub(super) fn is_unique_isolated(window: &Window, timeout_ms: u64) -> bool {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let request = Request {
        orig: window.orig.iter().map(Encoded::from).collect(),
        alt: window.alt.iter().map(Encoded::from).collect(),
        known: window.known.iter().copied().collect(),
        target: window.target,
        timeout_ms,
    };
    let Ok(payload) = serde_json::to_vec(&request) else {
        return false;
    };
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    let Ok(mut child) = Command::new(executable)
        .arg("solve-window")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let written = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(&payload).is_ok());
    if !written {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }

    let deadline = std::time::Instant::now()
        + std::time::Duration::from_millis(timeout_ms.saturating_mul(2) + 1000);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
            Err(_) => return false,
        }
    }
    let mut answer = String::new();
    child
        .stdout
        .take()
        .is_some_and(|mut stdout| stdout.read_to_string(&mut answer).is_ok())
        && answer.trim() == "unsat"
}

/// The `solve-window` subcommand: one request on stdin, `unsat`, `sat` or
/// `unknown` on stdout.
pub(crate) fn serve_one() -> color_eyre::eyre::Result<()> {
    use std::io::Read;

    let mut payload = Vec::new();
    std::io::stdin().read_to_end(&mut payload)?;
    let request: Request = serde_json::from_slice(&payload)?;
    let orig = request
        .orig
        .iter()
        .map(Encoded::decode)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| color_eyre::eyre::eyre!("malformed window constraint"))?;
    let alt = request
        .alt
        .iter()
        .map(Encoded::decode)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| color_eyre::eyre::eyre!("malformed window constraint"))?;
    let known = request.known.into_iter().collect();
    let verdict = is_unique(
        &Window {
            prime: &crate::translate::field_modulus(),
            orig: &orig,
            alt: &alt,
            known: &known,
            target: request.target,
        },
        request.timeout_ms,
    );
    println!(
        "{}",
        match verdict {
            Some(true) => "unsat",
            Some(false) => "sat",
            None => "unknown",
        }
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Request {
    orig: Vec<Encoded>,
    alt: Vec<Encoded>,
    known: Vec<usize>,
    target: usize,
    timeout_ms: u64,
}

/// `IRConstraint` on the wire; coefficients as decimal strings.
#[derive(Serialize, Deserialize)]
enum Encoded {
    Linear(Vec<(String, String)>),
    NonLinear(Vec<(String, String, String)>, Vec<(String, String)>),
    Or(Vec<Encoded>),
    VarEq(String, String),
    VarNeq(String, String),
}

impl From<&IRConstraint> for Encoded {
    fn from(constraint: &IRConstraint) -> Self {
        let linear = |terms: &[IRTerm]| {
            terms
                .iter()
                .map(|term| (term.coeff.to_string(), term.var.clone()))
                .collect()
        };
        match constraint {
            IRConstraint::Linear(terms) => Encoded::Linear(linear(terms)),
            IRConstraint::NonLinear {
                lhs_terms,
                rhs_terms,
            } => Encoded::NonLinear(
                lhs_terms
                    .iter()
                    .map(|term| {
                        (
                            term.coeff.to_string(),
                            term.var_a.clone(),
                            term.var_b.clone(),
                        )
                    })
                    .collect(),
                linear(rhs_terms),
            ),
            IRConstraint::Or(subs) => Encoded::Or(subs.iter().map(Encoded::from).collect()),
            IRConstraint::VarEq(var, value) => Encoded::VarEq(var.clone(), value.to_string()),
            IRConstraint::VarNeq(a, b) => Encoded::VarNeq(a.clone(), b.clone()),
        }
    }
}

impl Encoded {
    fn decode(&self) -> Option<IRConstraint> {
        let number = |text: &str| text.parse::<BigUint>().ok();
        let linear = |terms: &[(String, String)]| {
            terms
                .iter()
                .map(|(coeff, var)| {
                    Some(IRTerm {
                        coeff: number(coeff)?,
                        var: var.clone(),
                    })
                })
                .collect::<Option<Vec<_>>>()
        };
        Some(match self {
            Encoded::Linear(terms) => IRConstraint::Linear(linear(terms)?),
            Encoded::NonLinear(lhs, rhs) => IRConstraint::NonLinear {
                lhs_terms: lhs
                    .iter()
                    .map(|(coeff, a, b)| {
                        Some(IRProductTerm {
                            coeff: number(coeff)?,
                            var_a: a.clone(),
                            var_b: b.clone(),
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
                rhs_terms: linear(rhs)?,
            },
            Encoded::Or(subs) => {
                IRConstraint::Or(subs.iter().map(Encoded::decode).collect::<Option<_>>()?)
            }
            Encoded::VarEq(var, value) => IRConstraint::VarEq(var.clone(), number(value)?),
            Encoded::VarNeq(a, b) => IRConstraint::VarNeq(a.clone(), b.clone()),
        })
    }
}

/// `Some(true)` on `UNSAT` (the target is unique even in this window),
/// `Some(false)` on `SAT`, `None` when cvc5 gave up.
///
/// The split engine is fast but not trusted with a proof: cvc5 1.3.1's
/// `ff-solver=split` answers `UNSAT` on satisfiable windows (the fixture
/// `split_gb_false_unsat.json` is one, found by the mutation benchmark, where
/// it let `scan` call a certified-nondet output `verified`). Its `SAT` only
/// ever leaves a wire undetermined, so it is used to reject quickly, and every
/// `UNSAT` it reports is re-decided by the default Gröbner-basis engine, the
/// one Picus relies on.
fn is_unique(window: &Window, timeout_ms: u64) -> Option<bool> {
    match decide(window, timeout_ms, "split") {
        Some(true) => decide(window, timeout_ms, "gb"),
        other => other,
    }
}

fn decide(window: &Window, timeout_ms: u64, engine: &str) -> Option<bool> {
    let tm = cvc5_ff::TermManager::new();
    let mut solver = cvc5_ff::Solver::new(&tm);
    solver.set_logic("QF_FF");
    solver.set_option("ff-solver", engine);
    solver.set_option("tlimit", &timeout_ms.to_string());
    let field = tm.mk_ff_sort(&window.prime.to_string(), 10);

    let target_x = format!("x{}", window.target);
    let target_y = format!("y{}", window.target);
    let mut names = BTreeSet::from([target_x.clone(), target_y.clone()]);
    for constraint in window.orig.iter().chain(window.alt) {
        collect_names(constraint, &mut names);
    }
    let vars: HashMap<String, cvc5_ff::Term> = names
        .iter()
        .map(|name| (name.clone(), tm.mk_const(field.clone(), name)))
        .collect();

    let element = |value: &str| tm.mk_ff_elem(value, field.clone(), 10);
    if let Some(x0) = vars.get("x0") {
        solver.assert_formula(tm.mk_term(cvc5_ff::Kind::Equal, &[x0.clone(), element("1")]));
    }
    for constraint in window.orig.iter().chain(window.alt) {
        if let Some(term) = build(&tm, &field, &vars, constraint) {
            solver.assert_formula(term);
        }
    }
    // Determined wires agree across the copies; only the ones this window
    // mentions in both copies matter.
    for (name, y) in &vars {
        let Some(wire) = name.strip_prefix('y').and_then(|n| n.parse::<usize>().ok()) else {
            continue;
        };
        if let (true, Some(x)) = (window.known.contains(&wire), vars.get(&format!("x{wire}"))) {
            solver.assert_formula(tm.mk_term(cvc5_ff::Kind::Equal, &[x.clone(), y.clone()]));
        }
    }
    let same = tm.mk_term(
        cvc5_ff::Kind::Equal,
        &[vars[&target_x].clone(), vars[&target_y].clone()],
    );
    solver.assert_formula(tm.mk_term(cvc5_ff::Kind::Not, &[same]));

    let result = solver.check_sat();
    if result.is_unsat() {
        Some(true)
    } else if result.is_sat() {
        Some(false)
    } else {
        None
    }
}

fn collect_names(constraint: &IRConstraint, names: &mut BTreeSet<String>) {
    match constraint {
        IRConstraint::Linear(terms) => names.extend(terms.iter().map(|term| term.var.clone())),
        IRConstraint::NonLinear {
            lhs_terms,
            rhs_terms,
        } => {
            for term in lhs_terms {
                names.insert(term.var_a.clone());
                names.insert(term.var_b.clone());
            }
            names.extend(rhs_terms.iter().map(|term| term.var.clone()));
        }
        IRConstraint::Or(subs) => {
            for sub in subs {
                collect_names(sub, names);
            }
        }
        IRConstraint::VarEq(var, _) => {
            names.insert(var.clone());
        }
        IRConstraint::VarNeq(a, b) => {
            names.insert(a.clone());
            names.insert(b.clone());
        }
    }
}

/// The same encoding as the Picus cvc5 backend, constraint for constraint.
fn build<'tm>(
    tm: &'tm cvc5_ff::TermManager,
    field: &cvc5_ff::Sort<'tm>,
    vars: &HashMap<String, cvc5_ff::Term<'tm>>,
    constraint: &IRConstraint,
) -> Option<cvc5_ff::Term<'tm>> {
    let element = |value: &BigUint| tm.mk_ff_elem(&value.to_string(), field.clone(), 10);
    let sum = |parts: Vec<cvc5_ff::Term<'tm>>| match parts.len() {
        0 => tm.mk_ff_elem("0", field.clone(), 10),
        1 => parts.into_iter().next().expect("one part"),
        _ => tm.mk_term(cvc5_ff::Kind::FiniteFieldAdd, &parts),
    };
    let linear = |terms: &[IRTerm]| -> Vec<cvc5_ff::Term<'tm>> {
        terms
            .iter()
            .map(|term| {
                tm.mk_term(
                    cvc5_ff::Kind::FiniteFieldMult,
                    &[element(&term.coeff), vars[&term.var].clone()],
                )
            })
            .collect()
    };
    let zero = || tm.mk_ff_elem("0", field.clone(), 10);
    match constraint {
        IRConstraint::Linear(terms) => {
            Some(tm.mk_term(cvc5_ff::Kind::Equal, &[sum(linear(terms)), zero()]))
        }
        IRConstraint::NonLinear {
            lhs_terms,
            rhs_terms,
        } => {
            let lhs = lhs_terms
                .iter()
                .map(|term| {
                    tm.mk_term(
                        cvc5_ff::Kind::FiniteFieldMult,
                        &[
                            element(&term.coeff),
                            vars[&term.var_a].clone(),
                            vars[&term.var_b].clone(),
                        ],
                    )
                })
                .collect();
            Some(tm.mk_term(cvc5_ff::Kind::Equal, &[sum(lhs), sum(linear(rhs_terms))]))
        }
        IRConstraint::Or(subs) => {
            let terms: Vec<_> = subs
                .iter()
                .filter_map(|sub| build(tm, field, vars, sub))
                .collect();
            match terms.len() {
                0 => None,
                1 => terms.into_iter().next(),
                _ => Some(tm.mk_term(cvc5_ff::Kind::Or, &terms)),
            }
        }
        IRConstraint::VarEq(var, value) => {
            Some(tm.mk_term(cvc5_ff::Kind::Equal, &[vars[var].clone(), element(value)]))
        }
        IRConstraint::VarNeq(a, b) => {
            let same = tm.mk_term(cvc5_ff::Kind::Equal, &[vars[a].clone(), vars[b].clone()]);
            Some(tm.mk_term(cvc5_ff::Kind::Not, &[same]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // cvc5's finite-field engine (CoCoA) keeps global state and crashes when
    // two solvers run in one process at once. Production never does that —
    // each window gets its own process — but the test harness runs tests on
    // parallel threads, so every test here takes this lock.
    static CVC5: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn term(coeff: BigUint, var: &str) -> IRTerm {
        IRTerm {
            coeff,
            var: var.to_string(),
        }
    }

    fn solve(orig: Vec<IRConstraint>, alt: Vec<IRConstraint>) -> Option<bool> {
        let _guard = CVC5.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Encode and decode on the way, as the child process would.
        let roundtrip = |constraints: &[IRConstraint]| {
            constraints
                .iter()
                .map(|constraint| {
                    let encoded = serde_json::to_vec(&Encoded::from(constraint)).unwrap();
                    serde_json::from_slice::<Encoded>(&encoded)
                        .unwrap()
                        .decode()
                        .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let prime = crate::translate::field_modulus();
        is_unique(
            &Window {
                prime: &prime,
                orig: &roundtrip(&orig),
                alt: &roundtrip(&alt),
                known: &BTreeSet::new(),
                target: 2,
            },
            5000,
        )
    }

    // w2 = 3 * w1 with w1 shared: unique.
    #[test]
    fn a_linear_function_of_a_shared_wire_is_unique() {
        let minus_three = crate::translate::field_modulus() - BigUint::from(3u8);
        let copy = |own: &str| {
            IRConstraint::Linear(vec![
                term(BigUint::from(1u8), own),
                term(minus_three.clone(), "x1"),
            ])
        };
        assert_eq!(solve(vec![copy("x2")], vec![copy("y2")]), Some(true));
    }

    // w2 * w2 = w1: both square roots satisfy it, so not unique.
    #[test]
    fn a_square_root_is_not_unique() {
        let copy = |own: &str| IRConstraint::NonLinear {
            lhs_terms: vec![IRProductTerm {
                coeff: BigUint::from(1u8),
                var_a: own.to_string(),
                var_b: own.to_string(),
            }],
            rhs_terms: vec![term(BigUint::from(1u8), "x1")],
        };
        assert_eq!(solve(vec![copy("x2")], vec![copy("y2")]), Some(false));
    }

    // Regression: a satisfiable window (two copies of `w3 = (w0 - w1) * w6 + w1`
    // with the quotient `w6` free, from a mutant with its `RANGE(w6, 1)`
    // removed) that cvc5 1.3.1's split engine calls UNSAT. Before the default
    // engine confirmed every split UNSAT, refinement marked `w3` determined and
    // `scan` reported a certified-nondet output `verified`.
    #[test]
    fn a_split_engine_unsat_is_not_trusted() {
        let _guard = CVC5.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let request: Request =
            serde_json::from_str(include_str!("split_gb_false_unsat.json")).unwrap();
        let decode = |constraints: &[Encoded]| {
            constraints
                .iter()
                .map(|constraint| constraint.decode().unwrap())
                .collect::<Vec<_>>()
        };
        let (orig, alt) = (decode(&request.orig), decode(&request.alt));
        let prime = crate::translate::field_modulus();
        let known = request.known.iter().copied().collect();
        let window = Window {
            prime: &prime,
            orig: &orig,
            alt: &alt,
            known: &known,
            target: request.target,
        };
        // The bug itself: if this starts failing, cvc5 fixed it.
        assert_eq!(decide(&window, 5000, "split"), Some(true));
        assert_eq!(decide(&window, 5000, "gb"), Some(false));
        assert_eq!(is_unique(&window, 5000), Some(false));
    }
}
