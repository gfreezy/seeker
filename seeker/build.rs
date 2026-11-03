fn main() {
    println!(
        "cargo:rustc-env=SEEKER_BUILD_TARGET={}",
        std::env::var("TARGET").expect("Cargo must provide the build target")
    );
}
