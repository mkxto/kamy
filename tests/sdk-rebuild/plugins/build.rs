fn main() {
    for name in ["SDK_TRACE_RVA", "SDK_TABLE_BYTES"] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = std::env::var(name).unwrap_or_else(|_| panic!("{name} MUST be supplied by sdk-rebuild produce"));
        let _: usize = value.parse().unwrap_or_else(|_| panic!("{name} MUST be a decimal unsigned integer"));
        println!("cargo:rustc-env={name}={value}");
    }
}
