use crate::config::rule::{Action, ProxyRules};
use log::{debug, error};
use shadowsocks::relay::boxed_future;
use sled::Db;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::prelude::{future, Async, Future};
use trust_dns::op::LowerQuery;
use trust_dns::proto::rr::{RData, Record};
use trust_dns::rr::{LowerName, Name};
use trust_dns_resolver::AsyncResolver;
use trust_dns_server::authority::{Authority, LookupError, LookupObject, MessageRequest, ZoneType};
use trust_dns_server::proto::op::ResponseCode;
use trust_dns_server::proto::rr::dnssec::SupportedAlgorithms;
use trust_dns_server::proto::rr::RecordType;

const NEXT_IP: &str = "next_ip";

struct Inner {
    cache: Db,
    next_ip: u32,
    async_resolver: AsyncResolver,
    rules: ProxyRules,
}

impl Inner {
    fn new<P: AsRef<Path>>(
        path: P,
        next_ip: u32,
        async_resolver: AsyncResolver,
        rules: ProxyRules,
    ) -> Self {
        let tree = Db::start_default(path).expect("open db error");
        let next_ip = match tree.get(NEXT_IP.as_bytes()) {
            Ok(Some(v)) => {
                let mut s = [0; 4];
                s.copy_from_slice(&v);
                u32::from_be_bytes(s)
            }
            _ => {
                tree.clear().unwrap();
                next_ip
            }
        };

        Inner {
            cache: tree,
            next_ip,
            async_resolver,
            rules,
        }
    }

    fn lookup_host(&self, addr: String) -> impl Future<Item = String, Error = io::Error> {
        debug!("lookup host: {}", &addr);
        if let Some(host) = self.cache.get(addr.as_bytes()).unwrap() {
            future::finished(String::from_utf8(host.to_vec()).unwrap())
        } else {
            future::err(io::Error::new(
                io::ErrorKind::Other,
                "no host found".to_string(),
            ))
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

#[derive(Clone)]
pub struct LocalAuthority {
    origin: LowerName,
    inner: Arc<Mutex<Inner>>,
}

impl LocalAuthority {
    pub fn new<P: AsRef<Path>>(
        path: P,
        next_ip: Ipv4Addr,
        async_resolver: AsyncResolver,
        rules: ProxyRules,
    ) -> Self {
        let n = u32::from_be_bytes(next_ip.octets());
        debug!("LocalAuthority.new next_ip: {}", n);
        LocalAuthority {
            origin: Name::root().into(),
            inner: Arc::new(Mutex::new(Inner::new(path, n, async_resolver, rules))),
        }
    }

    pub fn lookup_ip(&self, domain: String) -> LookupIP {
        debug!("lookup ip {}", &domain);
        LookupIP {
            domain,
            inner: self.inner.clone(),
            lookup_future: None,
        }
    }

    pub fn lookup_host(&self, addr: String) -> LookupHost {
        LookupHost {
            addr,
            inner: self.inner.clone(),
        }
    }
}

pub struct LookupIP {
    domain: String,
    inner: Arc<Mutex<Inner>>,
    lookup_future: Option<Box<dyn Future<Item = Option<String>, Error = io::Error> + Send>>,
}

impl Future for LookupIP {
    type Item = Option<String>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        if let Some(ref mut fut) = self.lookup_future {
            fut.poll()
        } else {
            let mut guard = self.inner.lock().unwrap();
            let domain = self.domain.trim_end_matches('.').to_string();
            if let Some(addr) = guard.cache.get(&domain).expect("get domain") {
                let ip = String::from_utf8(addr.to_vec()).unwrap();
                debug!("resolve from cache, domain: {}, ip: {}", &domain, &ip);
                Ok(Async::Ready(Some(ip)))
            } else {
                let default_action = guard.rules.default_action();
                let action = guard
                    .rules
                    .action_for_domain(&domain)
                    .unwrap_or(default_action);
                match action {
                    Action::Reject => Ok(Async::Ready(Some("127.0.0.1".to_string()))),
                    Action::Direct => {
                        let domain2 = domain.clone();
                        debug!("direct, domain: {}", &domain2);
                        self.lookup_future = Some(boxed_future(
                            guard
                                .async_resolver
                                .lookup_ip(domain.as_str())
                                .map(move |ips| {
                                    let ip = ips.into_iter().next().unwrap();
                                    debug!("resolve domain {}, ip: {}", &domain, ip);
                                    Some(ip.to_string())
                                })
                                .map_err(move |e| {
                                    error!("resolve domain {}: {}", domain2, e);
                                    io::ErrorKind::Other.into()
                                }),
                        ));
                        self.lookup_future.as_mut().unwrap().poll()
                    }
                    Action::Proxy => {
                        let addr = guard.gen_ipaddr();
                        debug!("resolve to tun, domain: {}, ip: {}", &domain, &addr);

                        guard
                            .cache
                            .set(NEXT_IP.as_bytes(), &guard.next_ip.to_be_bytes())
                            .unwrap();
                        guard.cache.set(domain.as_bytes(), addr.as_bytes()).unwrap();
                        guard.cache.set(addr.as_bytes(), domain.as_bytes()).unwrap();
                        Ok(Async::Ready(Some(addr)))
                    }
                }
            }
        }
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
        let guard = self.inner.lock().unwrap();
        guard.lookup_host(self.addr.clone()).poll()
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

    fn update(&mut self, _update: &MessageRequest) -> Result<bool, ResponseCode> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn lookup(
        &self,
        lower_name: &LowerName,
        _rtype: RecordType,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Self::LookupFuture {
        let name: Name = lower_name.into();
        Box::new(
            self.lookup_ip(name.to_string())
                .map(|ip| {
                    if let Some(ip) = ip {
                        let mut record = Record::with(name, RecordType::A, 60);
                        record.set_rdata(RData::A(ip.parse().unwrap()));
                        LocalLookup(vec![record])
                    } else {
                        LocalLookup(vec![])
                    }
                })
                .map_err(LookupError::Io),
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
        _name: &LowerName,
        _is_secure: bool,
        _supported_algorithms: SupportedAlgorithms,
    ) -> Self::LookupFuture {
        unimplemented!()
    }
}
