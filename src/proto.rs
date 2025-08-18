pub mod fkms {
    pub mod v1 {
        tonic::include_proto!("fkms.v1");
        pub const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("fkms_v1_descriptor");
    }
}
