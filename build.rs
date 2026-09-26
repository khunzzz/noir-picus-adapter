//! Link support for building against a *prebuilt* cvc5.
//!
//! `picus-smt`'s `cvc5-ff-sys` compiles cvc5 from source by default, which
//! takes tens of minutes and several GB per machine. Setting `CVC5_LIB_DIR` to
//! an official cvc5 static release makes it skip that, but its hard-coded link
//! list (`cvc5 cadical picpoly picpolyxx gmp cocoa`) misses libraries the
//! release archives ship separately — CLN and GLPK — so the final link fails
//! with undefined `cln::*` symbols. Add whatever of those the archive actually
//! contains.
fn main() {
    println!("cargo:rerun-if-env-changed=CVC5_LIB_DIR");

    let Ok(lib_dir) = std::env::var("CVC5_LIB_DIR") else {
        return;
    };

    // These have to land *after* `libcvc5.a` on the linker command line,
    // which `cargo:rustc-link-lib` cannot guarantee across crates, so they go
    // through raw link args instead.
    println!("cargo:rustc-link-arg=-L{lib_dir}");
    for library in ["cln", "glpk"] {
        if std::path::Path::new(&lib_dir)
            .join(format!("lib{library}.a"))
            .exists()
        {
            println!("cargo:rustc-link-arg=-l:lib{library}.a");
        }
    }
}
