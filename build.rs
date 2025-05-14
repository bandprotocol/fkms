use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(out_dir.join("kms_v1_descriptor.bin"))
        .compile_protos(
            &["proto/kms/v1/signer.proto"], // specify the proto files to compile
            &["proto/kms"], // specify the root location to search proto dependencies
        )
        .unwrap();
}
