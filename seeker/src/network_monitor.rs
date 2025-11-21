#[cfg(target_os = "macos")]
mod macos {
    use std::sync::Arc;
    use system_configuration::core_foundation::array::CFArray;
    use system_configuration::core_foundation::runloop::{CFRunLoop, kCFRunLoopCommonModes};
    use system_configuration::core_foundation::string::CFString;
    use system_configuration::dynamic_store::{
        SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
    };
    use tokio::sync::mpsc;
    use tracing::{error, info};

    /// Monitor network changes on macOS
    pub fn spawn_network_monitor(tx: mpsc::UnboundedSender<()>) {
        std::thread::spawn(move || {
            info!("Starting macOS network monitor");

            let tx_arc = Arc::new(tx);

            let callback_context = SCDynamicStoreCallBackContext {
                callout: network_change_callback,
                info: tx_arc,
            };

            let store = SCDynamicStoreBuilder::new("seeker-network-monitor")
                .callback_context(callback_context)
                .build();

            // Monitor network interface changes and IPv4/IPv6 state changes
            let watch_keys = CFArray::<CFString>::from_CFTypes(&[]);
            let watch_patterns = CFArray::from_CFTypes(&[
                CFString::from("State:/Network/Interface/.*/Link"),
                CFString::from("State:/Network/Global/IPv4"),
                CFString::from("State:/Network/Global/IPv6"),
            ]);

            if !store.set_notification_keys(&watch_keys, &watch_patterns) {
                error!("Failed to set notification keys for network monitor");
                return;
            }

            let run_loop_source = store.create_run_loop_source();
            let run_loop = CFRunLoop::get_current();
            run_loop.add_source(&run_loop_source, unsafe { kCFRunLoopCommonModes });

            info!("Network monitor configured, starting run loop");
            CFRunLoop::run_current();
        });
    }

    fn network_change_callback(
        _store: SCDynamicStore,
        changed_keys: CFArray<CFString>,
        info: &mut Arc<mpsc::UnboundedSender<()>>,
    ) {
        let mut meaningful_change = false;
        for key in changed_keys.iter() {
            let key_str = format!("{}", &*key);
            if key_str.contains("vmenet") || key_str.contains("bridge") || key_str.contains("utun")
            {
                tracing::debug!("Ignored network change for virtual interface: {}", key_str);
                continue;
            }
            tracing::info!("Network change detected: {}", key_str);
            meaningful_change = true;
        }

        if meaningful_change && let Err(e) = info.send(()) {
            tracing::error!("Failed to send network change notification: {}", e);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use netlink_packet_route::link::LinkAttribute;
    use tokio::sync::mpsc;
    use tracing::{error, info};

    /// Monitor network changes on Linux using Netlink
    pub fn spawn_network_monitor(tx: mpsc::UnboundedSender<()>) {
        tokio::spawn(async move {
            info!("Starting Linux network monitor");

            // Keep retrying if the monitor fails or stream ends
            loop {
                match monitor_network_changes(tx.clone()).await {
                    Ok(()) => {
                        info!("Network monitor stream ended, restarting in 1 second");
                    }
                    Err(e) => {
                        error!("Network monitor error: {}, restarting in 1 second", e);
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });
    }

    async fn monitor_network_changes(
        tx: mpsc::UnboundedSender<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use bytes::BytesMut;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use netlink_packet_route::RouteNetlinkMessage;
        use netlink_sys::{AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket};
        use netlink_sys::protocols::NETLINK_ROUTE;

        // Create a netlink socket subscribed to network change events
        // RTMGRP_LINK: link state changes (interface up/down)
        // RTMGRP_IPV4_IFADDR: IPv4 address changes
        // RTMGRP_IPV6_IFADDR: IPv6 address changes
        let groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
        let mut socket = TokioSocket::new(NETLINK_ROUTE)?;
        let addr = SocketAddr::new(0, groups);
        socket.socket_mut().bind(&addr)?;

        info!("Linux network monitor started, listening for network changes");

        // Continuously listen for Netlink messages
        loop {
            let mut buf = BytesMut::with_capacity(4096);

            match socket.recv(&mut buf).await {
                Ok(_) => {},
                Err(e) => {
                    error!("Error receiving netlink message: {}", e);
                    continue;
                }
            };

            // Parse netlink messages
            let msg = match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf[..]) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::debug!("Failed to parse netlink message: {}", e);
                    continue;
                }
            };

            if let NetlinkPayload::InnerMessage(route_msg) = msg.payload {
                match route_msg {
                    RouteNetlinkMessage::NewLink(link) | RouteNetlinkMessage::DelLink(link) => {
                        let ifname = link.attributes.iter()
                            .find_map(|attr| {
                                if let LinkAttribute::IfName(name) = attr {
                                    Some(name.clone())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| "unknown".to_string());

                        // Ignore virtual interfaces
                        if ifname.contains("docker") || ifname.contains("veth")
                            || ifname.contains("br-") || ifname.starts_with("tun")
                            || ifname.starts_with("utun") || ifname.starts_with("lo") {
                            tracing::debug!("Ignored network change for virtual interface: {}", ifname);
                            continue;
                        }

                        info!("Network link change detected: {}", ifname);
                        let _ = tx.send(());
                    }
                    RouteNetlinkMessage::NewAddress(_) | RouteNetlinkMessage::DelAddress(_) => {
                        info!("Network address change detected");
                        let _ = tx.send(());
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod stub {
    use tokio::sync::mpsc;

    /// Stub implementation for unsupported platforms
    pub fn spawn_network_monitor(_tx: mpsc::UnboundedSender<()>) {
        tracing::info!("Network monitoring is only supported on macOS and Linux");
    }
}

#[cfg(target_os = "macos")]
pub use macos::spawn_network_monitor;

#[cfg(target_os = "linux")]
pub use linux::spawn_network_monitor;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub use stub::spawn_network_monitor;
