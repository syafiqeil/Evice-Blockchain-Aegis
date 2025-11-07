// evice_blockchain/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure().compile_protos(&["rpc.proto"], &["."])?;
    Ok(())
}
