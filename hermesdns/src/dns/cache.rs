//! a threadsafe cache for DNS information

use chrono::{DateTime, Local, TimeDelta};
use std::clone::Clone;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{Error, Result};
use std::sync::{Arc, RwLock};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};

pub enum CacheState {
    PositiveCache,
    NegativeCache,
    NotCached,
}

#[derive(Clone, Eq, Debug)]
pub struct RecordEntry {
    pub record: DnsRecord,
    pub timestamp: DateTime<Local>,
}

impl PartialEq<RecordEntry> for RecordEntry {
    fn eq(&self, other: &RecordEntry) -> bool {
        self.record == other.record
    }
}

impl Hash for RecordEntry {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.record.hash(state);
    }
}

#[derive(Clone, Debug)]
pub enum RecordSet {
    NoRecords {
        #[allow(unused)]
        qtype: QueryType,
        ttl: u32,
        timestamp: DateTime<Local>,
    },
    Records {
        #[allow(unused)]
        qtype: QueryType,
        records: HashSet<RecordEntry>,
    },
}

#[derive(Clone, Debug)]
pub struct DomainEntry {
    #[allow(unused)]
    pub domain: String,
    pub record_types: HashMap<QueryType, RecordSet>,
    pub hits: u32,
    pub updates: u32,
}

impl DomainEntry {
    pub fn new(domain: String) -> DomainEntry {
        DomainEntry {
            domain,
            record_types: HashMap::new(),
            hits: 0,
            updates: 0,
        }
    }

    pub fn store_nxdomain(&mut self, qtype: QueryType, ttl: u32) {
        self.updates += 1;

        let new_set = RecordSet::NoRecords {
            qtype,
            ttl,
            timestamp: Local::now(),
        };

        self.record_types.insert(qtype, new_set);
    }

    pub fn store_record(&mut self, rec: &DnsRecord) {
        self.updates += 1;

        let entry = RecordEntry {
            record: rec.clone(),
            timestamp: Local::now(),
        };

        if let Some(&mut RecordSet::Records {
            ref mut records, ..
        }) = self.record_types.get_mut(&rec.get_querytype())
        {
            if records.contains(&entry) {
                records.remove(&entry);
            }

            records.insert(entry);
            return;
        }

        let mut records = HashSet::new();
        records.insert(entry);

        let new_set = RecordSet::Records {
            qtype: rec.get_querytype(),
            records,
        };

        self.record_types.insert(rec.get_querytype(), new_set);
    }

    pub fn get_cache_state(&self, qtype: QueryType) -> CacheState {
        match self.record_types.get(&qtype) {
            Some(RecordSet::Records { records, .. }) => {
                let now = Local::now();

                let mut valid_count = 0;
                for entry in records {
                    let Some(ttl_offset) = TimeDelta::try_seconds(entry.record.get_ttl() as i64)
                    else {
                        return CacheState::NotCached;
                    };
                    let expires = entry.timestamp + ttl_offset;
                    if expires < now {
                        continue;
                    }

                    if entry.record.get_querytype() == qtype {
                        valid_count += 1;
                    }
                }

                if valid_count > 0 {
                    CacheState::PositiveCache
                } else {
                    CacheState::NotCached
                }
            }
            Some(&RecordSet::NoRecords { ttl, timestamp, .. }) => {
                let now = Local::now();
                let Some(ttl_offset) = TimeDelta::try_seconds(ttl as i64) else {
                    return CacheState::NotCached;
                };
                let expires = timestamp + ttl_offset;

                if expires < now {
                    CacheState::NotCached
                } else {
                    CacheState::NegativeCache
                }
            }
            None => CacheState::NotCached,
        }
    }

    pub fn fill_queryresult(&self, qtype: QueryType, result_vec: &mut Vec<DnsRecord>) {
        let now = Local::now();

        let current_set = match self.record_types.get(&qtype) {
            Some(x) => x,
            None => return,
        };

        if let RecordSet::Records { records, .. } = current_set {
            for entry in records {
                let Some(ttl_offset) = TimeDelta::try_seconds(entry.record.get_ttl() as i64) else {
                    continue;
                };
                let expires = entry.timestamp + ttl_offset;
                if expires < now {
                    continue;
                }

                if entry.record.get_querytype() == qtype {
                    result_vec.push(entry.record.clone());
                }
            }
        }
    }
}

#[derive(Default)]
pub struct Cache {
    domain_entries: BTreeMap<String, Arc<DomainEntry>>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            domain_entries: BTreeMap::new(),
        }
    }

    fn get_cache_state(&mut self, qname: &str, qtype: QueryType) -> CacheState {
        match self.domain_entries.get(qname) {
            Some(x) => x.get_cache_state(qtype),
            None => CacheState::NotCached,
        }
    }

    fn fill_queryresult(
        &mut self,
        qname: &str,
        qtype: QueryType,
        result_vec: &mut Vec<DnsRecord>,
        increment_stats: bool,
    ) {
        if let Some(domain_entry) = self.domain_entries.get_mut(qname).and_then(Arc::get_mut) {
            if increment_stats {
                domain_entry.hits += 1
            }

            domain_entry.fill_queryresult(qtype, result_vec);
        }
    }

    fn lookup(&mut self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        match self.get_cache_state(qname, qtype) {
            CacheState::PositiveCache => {
                let mut qr = DnsPacket::new();
                self.fill_queryresult(qname, qtype, &mut qr.answers, true);
                self.fill_queryresult(qname, QueryType::NS, &mut qr.authorities, false);

                Some(qr)
            }
            CacheState::NegativeCache => {
                let mut qr = DnsPacket::new();
                qr.header.rescode = ResultCode::NXDOMAIN;

                Some(qr)
            }
            CacheState::NotCached => None,
        }
    }

    fn store(&mut self, records: &[DnsRecord]) {
        for rec in records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue,
            };

            if let Some(ref mut rs) = self.domain_entries.get_mut(&domain).and_then(Arc::get_mut) {
                rs.store_record(rec);
                continue;
            }

            let mut rs = DomainEntry::new(domain.clone());
            rs.store_record(rec);
            self.domain_entries.insert(domain.clone(), Arc::new(rs));
        }
    }

    fn store_nxdomain(&mut self, qname: &str, qtype: QueryType, ttl: u32) {
        if let Some(ref mut rs) = self.domain_entries.get_mut(qname).and_then(Arc::get_mut) {
            rs.store_nxdomain(qtype, ttl);
            return;
        }

        let mut rs = DomainEntry::new(qname.to_string());
        rs.store_nxdomain(qtype, ttl);
        self.domain_entries.insert(qname.to_string(), Arc::new(rs));
    }
}

#[derive(Default)]
pub struct SynchronizedCache {
    pub cache: RwLock<Cache>,
}

impl SynchronizedCache {
    pub fn new() -> SynchronizedCache {
        SynchronizedCache {
            cache: RwLock::new(Cache::new()),
        }
    }

    #[allow(dead_code)]
    pub fn list(&self) -> Result<Vec<Arc<DomainEntry>>> {
        let cache = match self.cache.read() {
            Ok(x) => x,
            Err(_) => return Err(Error::other("Failed to acquire lock")),
        };

        let mut list = Vec::new();

        let values = cache.domain_entries.values();
        for rs in values {
            list.push(rs.clone());
        }

        Ok(list)
    }

    pub fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return None,
        };

        cache.lookup(qname, qtype)
    }

    pub fn store(&self, records: &[DnsRecord]) -> Result<()> {
        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return Err(Error::other("Failed to acquire lock")),
        };

        cache.store(records);

        Ok(())
    }

    pub fn store_nxdomain(&self, qname: &str, qtype: QueryType, ttl: u32) -> Result<()> {
        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return Err(Error::other("Failed to acquire lock")),
        };

        cache.store_nxdomain(qname, qtype, ttl);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::dns::protocol::{DnsRecord, QueryType, ResultCode, TransientTtl};

    #[test]
    fn test_cache() {
        let mut cache = Cache::new();

        // Verify that no data is returned when nothing is present
        assert!(cache.lookup("www.google.com", QueryType::A).is_none());

        // Register a negative cache entry
        cache.store_nxdomain("www.google.com", QueryType::A, 3600);

        // Verify that we get a response, with the NXDOMAIN flag set
        if let Some(packet) = cache.lookup("www.google.com", QueryType::A) {
            assert_eq!(ResultCode::NXDOMAIN, packet.header.rescode);
        }

        // Register a negative cache entry with no TTL
        cache.store_nxdomain("www.yahoo.com", QueryType::A, 0);

        // And check that no such result is actually returned, since it's expired
        if cache.lookup("www.yahoo.com", QueryType::A).is_some() {
            panic!()
        }

        // Now add some actual records
        let records = vec![
            DnsRecord::A {
                domain: "www.google.com".to_string(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600),
            },
            DnsRecord::A {
                domain: "www.yahoo.com".to_string(),
                addr: "127.0.0.2".parse().unwrap(),
                ttl: TransientTtl(0),
            },
            DnsRecord::CNAME {
                domain: "www.microsoft.com".to_string(),
                host: "www.somecdn.com".to_string(),
                ttl: TransientTtl(3600),
            },
        ];

        cache.store(&records);

        // Test for successful lookup
        if let Some(packet) = cache.lookup("www.google.com", QueryType::A) {
            assert_eq!(records[0], packet.answers[0]);
        } else {
            panic!();
        }

        // Test for failed lookup, since no CNAME's are known for this domain
        if cache.lookup("www.google.com", QueryType::CNAME).is_some() {
            panic!();
        }

        // Check for successful CNAME lookup
        if let Some(packet) = cache.lookup("www.microsoft.com", QueryType::CNAME) {
            assert_eq!(records[2], packet.answers[0]);
        } else {
            panic!();
        }

        // This lookup should fail, since it has expired due to the 0 second TTL
        if cache.lookup("www.yahoo.com", QueryType::A).is_some() {
            panic!();
        }

        let records2 = vec![DnsRecord::A {
            domain: "www.yahoo.com".to_string(),
            addr: "127.0.0.2".parse().unwrap(),
            ttl: TransientTtl(3600),
        }];

        cache.store(&records2);

        // And now it should succeed, since the record has been store
        if cache.lookup("www.yahoo.com", QueryType::A).is_none() {
            panic!();
        }

        // Check stat counter behavior
        assert_eq!(3, cache.domain_entries.len());
        assert_eq!(1, cache.domain_entries.get("www.google.com").unwrap().hits);
        assert_eq!(
            2,
            cache.domain_entries.get("www.google.com").unwrap().updates
        );
        assert_eq!(1, cache.domain_entries.get("www.yahoo.com").unwrap().hits);
        assert_eq!(
            3,
            cache.domain_entries.get("www.yahoo.com").unwrap().updates
        );
        assert_eq!(
            1,
            cache
                .domain_entries
                .get("www.microsoft.com")
                .unwrap()
                .updates
        );
        assert_eq!(
            1,
            cache.domain_entries.get("www.microsoft.com").unwrap().hits
        );
    }
}
