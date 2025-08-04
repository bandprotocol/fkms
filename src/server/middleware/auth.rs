use std::error::Error;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};

use http::{Request, Response};
use prost::Message;
use tokio_stream::{Stream, StreamExt};
use tonic::body::Body;
use tonic::codec::Streaming;
use tonic::codec::{Codec, CompressionEncoding, ProstCodec};
use tonic::metadata::MetadataMap;
use tonic::{IntoRequest, Request as TonicRequest};
use tonic::{Status, body};
use tower::{Layer, Service};

use crate::proto::kms::v1::{SignEvmRequest, SignEvmResponse};
use crate::server::middleware::auth::store::Store;

pub mod store;

const DEFAULT_HEADER_API_KEY: &str = "api-key";

#[derive(Debug, Clone, Default)]
pub struct AuthMiddlewareLayer<S: Store> {
    pub store: S,
    pub header_api_key: String,
}

impl<S: Store> AuthMiddlewareLayer<S> {
    pub fn new(store: S, header_api_key: Option<String>) -> Self {
        let header_api_key = header_api_key.unwrap_or_else(|| DEFAULT_HEADER_API_KEY.to_string());
        Self {
            store,
            header_api_key,
        }
    }
}

impl<S1, S2: Store> Layer<S1> for AuthMiddlewareLayer<S2> {
    type Service = AuthMiddleware<S1, S2>;

    fn layer(&self, service: S1) -> Self::Service {
        AuthMiddleware {
            inner: service,
            store: self.store.clone(),
            header_api_key: self.header_api_key.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthMiddleware<S1, S2> {
    inner: S1,
    store: S2,
    header_api_key: String,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl<S1, S2, ReqBody, ResBody> Service<Request<ReqBody>> for AuthMiddleware<S1, S2>
where
    S1: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S1::Future: Send + 'static,
    S1::Error: Into<Box<dyn Error + Send + Sync>>,
    ReqBody: Send + 'static + Body,
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S2: Store,
{
    type Response = S1::Response;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let cloned_inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, cloned_inner);

        let store = self.store.clone();
        let header_api_key = self.header_api_key.clone();

        Box::pin(async move {
            let mut req: Request<ReqBody> = req;
            let request_body = req.body_mut();
            let body = request_body.data();

            // let (parts, body) = req.into_parts();

            let mut stream = pin!(Streaming::new_request(
                ProstCodec::<SignEvmResponse, SignEvmRequest>::default().decoder(),
                *body,
                /* no compression: */ None::<CompressionEncoding>,
                /* default max message size: */ None,
            ));

            let message = stream
                .try_next()
                .await?
                .ok_or_else(|| Status::internal("Missing request message."))?;

            // let api_key = parts
            //     .headers
            //     .get(header_api_key)
            //     .ok_or_else(|| Status::unauthenticated("Missing API key"))?
            //     .to_str()
            //     .map_err(|e| Status::internal(e.to_string()))?;

            // store.verify_api_key(api_key).await.map_err(|e| {
            //     Status::unauthenticated(format!("API key verification failed: {}", e))
            // })?;

            let new_req = Request::from_parts(parts, message);

            let response = inner.call(new_req).await.map_err(Into::into)?;
            Ok(response)
        })
    }
}
