//! The `ServerContext in this thread holds the common state across the server

use crate::dns::resolve::DnsResolver;

pub enum ResolveStrategy {
    Recursive,
    Forward { host: String, port: u16 },
}

pub struct ServerContext {
    pub listen: String,
    pub resolver: Box<dyn DnsResolver + Send + Sync>,
    pub allow_recursive: bool,
}

impl ServerContext {
    pub async fn new(
        listen: String,
        resolver: Box<dyn DnsResolver + Send + Sync>,
    ) -> ServerContext {
        Self {
            listen,
            resolver,
            allow_recursive: true,
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;

    use crate::dns::client::tests::{DnsStubClient, StubCallback};
    use crate::dns::resolve::{ForwardingDnsResolver, RecursiveDnsResolver};

    use super::*;

    pub async fn create_test_context(
        callback: Box<StubCallback>,
        resolve_strategy: ResolveStrategy,
    ) -> Arc<ServerContext> {
        match resolve_strategy {
            ResolveStrategy::Recursive => Arc::new(
                ServerContext::new(
                    "127.0.0.1:53".into(),
                    Box::new(
                        RecursiveDnsResolver::new(true, Box::new(DnsStubClient::new(callback)))
                            .await,
                    ),
                )
                .await,
            ),
            ResolveStrategy::Forward { host, port } => Arc::new(
                ServerContext::new(
                    "127.0.0.1:53".into(),
                    Box::new(
                        ForwardingDnsResolver::new(
                            (host, port),
                            true,
                            Box::new(DnsStubClient::new(callback)),
                        )
                        .await,
                    ),
                )
                .await,
            ),
        }
    }
}
