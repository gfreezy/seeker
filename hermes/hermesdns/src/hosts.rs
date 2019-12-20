use async_std::net::Ipv4Addr;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;

const HOSTS_PATH: &str = "/etc/hosts";

#[derive(Debug, PartialEq)]
pub struct Hosts {
    map: HashMap<String, Ipv4Addr>,
}

#[derive(Debug, PartialEq)]
pub struct LoadHostError(String);

impl Display for LoadHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Error for LoadHostError {}

impl From<String> for LoadHostError {
    fn from(s: String) -> Self {
        LoadHostError(s)
    }
}

impl From<&'static str> for LoadHostError {
    fn from(s: &str) -> Self {
        LoadHostError(s.to_string())
    }
}

impl Hosts {
    pub fn load() -> Result<Hosts, LoadHostError> {
        let mut f = File::open(HOSTS_PATH).map_err(|_| LoadHostError::from("open /etc/hosts"))?;
        let mut content = String::new();
        let _ = f
            .read_to_string(&mut content)
            .map_err(|_| LoadHostError::from("read /etc/hosts"))?;
        Hosts::parse(&content)
    }

    fn parse(content: &str) -> Result<Hosts, LoadHostError> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let strip_comment = line.chars().take_while(|c| *c != '#').collect::<String>();
            let segments = strip_comment.split_whitespace().collect::<Vec<&str>>();
            if segments.len() < 2 {
                continue;
            }
            let ip: Ipv4Addr = match segments[0].parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            for host in &segments[1..] {
                map.insert((*host).to_string(), ip);
            }
        }
        Ok(Hosts { map })
    }

    pub fn get(&self, domain: &str) -> Option<Ipv4Addr> {
        self.map.get(domain).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_hosts() {
        let hosts = Hosts::parse(
            r#"
##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1       localhost proxyhost
255.255.255.255     broadcasthost
::1                          localhost

# Updated automatically when Wi-Fi ip address changed
### BEGIN GENERATED CONTENT
192.168.2.111 influxdb registry.xiachufang.com pypi.xiachufang.com
### END GENERATED CONTENT

127.0.0.1  kubernetes.docker.internal
#
#
127.0.0.1  devdb
127.0.0.1  board-db-01 board-db-02 board-db-03 board-db-04
# Added by Docker Desktop
# To allow the same kube context to work on the host and the container:
127.0.0.1 kubernetes.docker.internal
# End of section
        "#,
        )
        .unwrap();
        let mut map = HashMap::new();
        map.insert(
            "kubernetes.docker.internal".to_string(),
            "127.0.0.1".parse().unwrap(),
        );
        map.insert(
            "registry.xiachufang.com".to_string(),
            "192.168.2.111".parse().unwrap(),
        );
        map.insert(
            "broadcasthost".to_string(),
            "255.255.255.255".parse().unwrap(),
        );
        map.insert("board-db-01".to_string(), "127.0.0.1".parse().unwrap());
        map.insert("board-db-02".to_string(), "127.0.0.1".parse().unwrap());
        map.insert("board-db-03".to_string(), "127.0.0.1".parse().unwrap());
        map.insert("board-db-04".to_string(), "127.0.0.1".parse().unwrap());
        map.insert("devdb".to_string(), "127.0.0.1".parse().unwrap());
        map.insert("proxyhost".to_string(), "127.0.0.1".parse().unwrap());
        map.insert("localhost".to_string(), "127.0.0.1".parse().unwrap());
        map.insert(
            "pypi.xiachufang.com".to_string(),
            "192.168.2.111".parse().unwrap(),
        );
        map.insert("influxdb".to_string(), "192.168.2.111".parse().unwrap());
        let expected = Hosts { map };
        assert_eq!(hosts.map.len(), expected.map.len());
        assert_eq!(hosts.map, expected.map);
    }
}
