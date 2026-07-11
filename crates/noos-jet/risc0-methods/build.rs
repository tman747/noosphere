#[cfg(unix)]
fn main() {
    use std::collections::HashMap;

    use risc0_build::{DockerOptions, GuestOptionsBuilder};

    println!("cargo:rerun-if-env-changed=NOOS_REBUILD_RISC0_GUEST");
    if std::env::var_os("NOOS_REBUILD_RISC0_GUEST").is_none() {
        return;
    }
    let options = GuestOptionsBuilder::default()
        .use_docker(DockerOptions::default())
        .build()
        .expect("static RISC Zero guest build options are valid");
    risc0_build::embed_methods_with_options(HashMap::from([("noos-jet-risc0-guest", options)]));
}

#[cfg(not(unix))]
fn main() {
    println!("cargo:rerun-if-env-changed=NOOS_REBUILD_RISC0_GUEST");
}
