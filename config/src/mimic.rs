use serde::Deserialize;

/// Seeker's userspace implementation of the Mimic wire protocol.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MimicConfig {
    pub enabled: bool,
    /// Physical outbound interface; derived from the route to the server when omitted.
    pub interface: Option<String>,
    /// Dedicated outer TUN interface; the OS selects an unused name by default.
    pub tun_name: Option<String>,
    pub mtu: u16,
    /// Must match the Mimic peer's padding setting.
    pub padding: MimicPadding,
}

impl Default for MimicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            tun_name: None,
            mtu: 1500,
            padding: MimicPadding::Fixed(0),
        }
    }
}

impl MimicConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1280..=9000).contains(&self.mtu) {
            return Err("mimic.mtu must be between 1280 and 9000".into());
        }
        if matches!(self.padding, MimicPadding::Fixed(n) if n > 16) {
            return Err("mimic.padding must be 0..16 or random".into());
        }
        for name in [&self.interface, &self.tun_name].into_iter().flatten() {
            if name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            {
                return Err(
                    "mimic interface names must contain 1..15 letters, digits, '.', '_' or '-'"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MimicPadding {
    Fixed(u8),
    Mode(RandomPadding),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RandomPadding {
    Random,
}

impl MimicPadding {
    pub fn len(&self, seq: u32, ack: u32) -> usize {
        match self {
            Self::Fixed(n) => *n as usize,
            Self::Mode(_) => (seq.wrapping_add(ack) % 11) as usize,
        }
    }

    pub fn max_len(&self) -> usize {
        match self {
            Self::Fixed(n) => *n as usize,
            Self::Mode(_) => 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ServerConfig;

    #[test]
    fn parses_both_server_formats_and_random_padding() {
        for yaml in [
            "name: test\naddr: example.com:443\nprotocol: hy2\n",
            "name: test\nserver: example.com\nport: 443\ntype: hysteria2\n",
        ] {
            let plain: ServerConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(plain.mimic(), None);
            let config: ServerConfig = serde_yaml::from_str(&format!(
                "{yaml}mimic:\n  enabled: true\n  padding: random\n"
            ))
            .unwrap();
            let mimic = config.mimic().unwrap();
            assert!(mimic.enabled);
            assert_eq!(mimic.mtu, 1500);
            assert_eq!(mimic.padding.len(u32::MAX, 1), 0);
        }
    }

    #[test]
    fn rejects_invalid_config_and_other_protocols() {
        let hy2 = "name: test\naddr: example.com:443\nprotocol: hy2\nmimic:\n  enabled: true\n";
        for field in [
            "mtu: 1000",
            "padding: 17",
            "interface: 'eth0;echo'",
            "xdpMode: skb",
            "padding: unknown",
        ] {
            assert!(
                serde_yaml::from_str::<ServerConfig>(&format!("{hy2}  {field}\n")).is_err(),
                "{field}"
            );
        }
        assert!(
            serde_yaml::from_str::<ServerConfig>(&hy2.replace("protocol: hy2", "protocol: socks5"))
                .is_err()
        );
    }
}
