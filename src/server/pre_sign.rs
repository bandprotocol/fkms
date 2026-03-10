use crate::codec::tss::TunnelPacket;

#[async_trait::async_trait]
pub trait PreSignHook: Send + Sync + 'static {
    async fn call(&self, packet: TunnelPacket) -> Result<(), tonic::Status>;
}
