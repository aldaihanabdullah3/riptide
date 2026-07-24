fn main() {
    println!("cargo:rerun-if-env-changed=C2_HOST");
    println!("cargo:rerun-if-env-changed=C2_PORT");
    println!("cargo:rerun-if-env-changed=BEACON_RATE");
    println!("cargo:rerun-if-env-changed=LABELLING_MARKER");
}
