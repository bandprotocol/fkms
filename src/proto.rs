pub mod kms {
    pub mod v1 {
        tonic::include_proto!("kms.v1");
        pub const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("kms_v1_descriptor");
    }
}
