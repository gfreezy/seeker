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

        if meaningful_change
            && let Err(e) = info.send(()) {
                tracing::error!("Failed to send network change notification: {}", e);
            }
    }
}

#[cfg(not(target_os = "macos"))]
mod stub {
    use tokio::sync::mpsc;

    /// Stub implementation for non-macOS platforms
    pub fn spawn_network_monitor(_tx: mpsc::UnboundedSender<()>) {
        tracing::info!("Network monitoring is only supported on macOS");
    }
}

#[cfg(target_os = "macos")]
pub use macos::spawn_network_monitor;

#[cfg(not(target_os = "macos"))]
pub use stub::spawn_network_monitor;
