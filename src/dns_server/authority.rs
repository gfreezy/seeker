use bimap::BiMap;
use log::debug;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Component::RootDir;
use std::sync::{Arc, Mutex};
use tokio::prelude::future::FutureResult;
use tokio::prelude::{future, Async, Future};
use tokio::spawn;
use tokio::sync::lock::{Lock, LockGuard};
use trust_dns::op::LowerQuery;
use trust_dns::proto::rr::{RData, Record};
use trust_dns::rr::{LowerName, Name};
use trust_dns_resolver::AsyncResolver;
use trust_dns_server::authority::{
    AuthLookup, Authority, LookupError, LookupObject, MessageRequest, ZoneType,
};
use trust_dns_server::proto::op::ResponseCode;
use trust_dns_server::proto::rr::dnssec::SupportedAlgorithms;
use trust_dns_server::proto::rr::RecordType;

#[derive(Clone)]
pub struct LocalAuthority {
    origin: LowerName,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    cache: BiMap<String, String>,
    next_ip: u32,
}

impl Inner {
    fn lookup_ip(&mut self, domain: String) -> impl Future<Item = String, Error = io::Error> {
        let domain = domain.trim_end_matches(".");
        let addr = if let Some(addr) = self.cache.get_by_left(&domain.to_string()) {
            addr.clone()
        } else {
            let addr = self.gen_ipaddr();
            self.cache.insert(domain.to_string(), addr.clone());
            addr
        };
        future::finished(addr)
    }

    fn lookup_host(&self, addr: String) -> impl Future<Item = String, Error = io::Error> {
        debug!("lookup host: {}", &addr);
        if let Some(host) = self.cache.get_by_right(&addr) {
            future::finished(host.clone())
        } else {
            future::err(io::ErrorKind::Other.into())
        }
    }

    fn gen_ipaddr(&mut self) -> String {
        let [a, b, c, d] = self.next_ip.to_be_bytes();
        self.next_ip += 1;
        // TODO: assert next_ip is not to large
        let addr = Ipv4Addr::new(a, b, c, d);
        debug!("Resolver.gen_ipaddr: {}", addr);
        addr.to_string()
    }
}

pub struct LookupIP {
    domain: String,
    inner: Arc<Mutex<Inner>>,
}

impl Future for LookupIP {
    type Item = String;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let mut guard = self.inner.lock().unwrap();
        guard.lookup_ip(self.domain.clone()).poll()
    }
}

pub struct LookupHost {
    addr: String,
    inner: Arc<Mutex<Inner>>,
}

impl Future for LookupHost {
    type Item = String;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let mut guard = self.inner.lock().unwrap();
        guard.lookup_host(self.addr.clone()).poll()
    }
}

impl LocalAuthority {
    pub fn new(next_ip: Ipv4Addr) -> Self {
        let n = u32::from_be_bytes(next_ip.octets());
        debug!("LocalAuthority.new next_ip: {}", n);
        LocalAuthority {
            origin: Name::root().into(),
            inner: Arc::new(Mutex::new(Inner {
                cache: BiMap::new(),
                next_ip: n,
            })),
        }
    }

    pub fn lookup_ip(&self, domain: String) -> LookupIP {
        debug!("lookup ip {}", &domain);
        LookupIP {
            domain,
            inner: self.inner.clone(),
        }
    }

    pub fn lookup_host(&self, addr: String) -> LookupHost {
        LookupHost {
            addr,
            inner: self.inner.clone(),
        }
    }
}

#[derive(Debug)]
pub struct LocalLookup(Vec<Record>);

impl LookupObject for LocalLookup {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Record> + Send + 'a> {
        Box::new(self.0.iter())
    }

    fn take_additionals(&mut self) -> Option<Box<dyn LookupObject>> {
        None
    }
}

impl Authority for LocalAuthority {
    type Lookup = LocalLookup;
    type LookupFuture = Box<dyn Future<Item = Self::Lookup, Error = LookupError> + Send>;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Forward
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn update(&mut self, update: &MessageRequest) -> Result<bool, ResponseCode> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn lookup(
        &self,
        lower_name: &LowerName,
        rtype: RecordType,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Self::LookupFuture {
        let name: Name = lower_name.into();
        Box::new(
            self.lookup_ip(name.to_string())
                .map(|ip| {
                    let mut record = Record::with(name, RecordType::A, 60);
                    record.set_rdata(RData::A(ip.parse().unwrap()));
                    LocalLookup(vec![record])
                })
                .map_err(|e| LookupError::Io(e)),
        )
    }

    fn search(
        &self,
        query: &LowerQuery,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Box<dyn Future<Item = Self::Lookup, Error = LookupError> + Send> {
        self.lookup(
            query.name(),
            query.query_type(),
            is_secure,
            supported_algorithms,
        )
    }

    fn get_nsec_records(
        &self,
        name: &LowerName,
        is_secure: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Self::LookupFuture {
        unimplemented!()
    }
}
