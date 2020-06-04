#![allow(clippy::unreadable_literal)]

mod dns;
mod hosts;

pub use dns::client::{DnsClient, DnsNetworkClient};
pub use dns::context::{ResolveStrategy, ServerContext};
pub use dns::protocol::{DnsPacket, DnsRecord, QueryType, TransientTtl};
pub use dns::resolve::{DnsResolver, ForwardingDnsResolver, RecursiveDnsResolver};
pub use dns::server::DnsUdpServer;
pub use hosts::{Hosts, LoadHostError};
