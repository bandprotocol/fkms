use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response};
use tonic::Status;
use tower::{Layer, Service};

use crate::server::middleware::store::Store;

const METADATA_API_KEY: &str = "api-key";

#[derive(Debug, Clone, Default)]
pub struct AuthMiddlewareLayer<S> {
    pub store: S,
}

impl<S> AuthMiddlewareLayer<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S1, S2: Clone> Layer<S1> for AuthMiddlewareLayer<S2> {
    type Service = AuthMiddleware<S1, S2>;

    fn layer(&self, service: S1) -> Self::Service {
        AuthMiddleware {
            inner: service,
            store: self.store.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthMiddleware<S1, S2> {
    inner: S1,
    store: S2,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl<S1, S2, ReqBody, ResBody> Service<Request<ReqBody>> for AuthMiddleware<S1, S2>
where
    S1: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S1::Future: Send + 'static,
    S1::Error: Into<Box<dyn Error + Send + Sync>>,
    ReqBody: Send + 'static,
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

        Box::pin(async move {
            let api_key = req
                .headers()
                .get(METADATA_API_KEY)
                .ok_or_else(|| Status::unauthenticated("Missing API key"))?
                .to_str()
                .map_err(|e| Status::internal(e.to_string()))?
                .to_string();

            store.verify_api_key(api_key).await.map_err(|e| {
                Status::unauthenticated(format!("API key verification failed: {}", e))
            })?;

            let response = inner.call(req).await.map_err(Into::into)?;
            Ok(response)
        })
    }
}
