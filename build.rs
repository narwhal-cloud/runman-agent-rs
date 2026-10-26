fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a vendored protoc unless the caller supplies one, so CI and cross
    // builds need no system protobuf installation.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build scripts are single-threaded at this point.
        unsafe { std::env::set_var("PROTOC", protoc) };
    }
    println!("cargo:rerun-if-changed=proto/agent.proto");
    tonic_prost_build::configure()
        .build_client(true)
        // The generated `connect(dst)` constructor clashes with the `Connect` rpc.
        .build_transport(false)
        // The server half is only used by the mock platform in tests/examples.
        .build_server(true)
        .compile_protos(&["proto/agent.proto"], &["proto"])?;
    Ok(())
}
