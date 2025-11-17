use std::io::{Read, Result, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tun_rs::{DeviceBuilder, InterruptEvent, SyncDevice};

/// A wrapper around tun-rs SyncDevice that provides compatibility with the original TunSocket interface
pub struct TunDevice {
    device: Arc<SyncDevice>,
    name: String,
    interrupt_event: Arc<InterruptEvent>,
}

impl Clone for TunDevice {
    fn clone(&self) -> Self {
        TunDevice {
            device: Arc::clone(&self.device),
            name: self.name.clone(),
            interrupt_event: Arc::clone(&self.interrupt_event),
        }
    }
}

impl TunDevice {
    /// Create a new TUN device with the given name
    pub fn new(name: &str) -> Result<Self> {
        let device = DeviceBuilder::new()
            .name(name)
            // TODO: Enable multi_queue when platform supports it
            // .multi_queue(true)
            .build_sync()
            .map_err(std::io::Error::other)?;

        let actual_name = device.name()?;

        Ok(TunDevice {
            device: Arc::new(device),
            name: actual_name,
            interrupt_event: Arc::new(InterruptEvent::new()?),
        })
    }

    /// Create a new TUN device with IPv4 configuration
    pub fn new_with_ipv4(
        name: &str,
        address: Ipv4Addr,
        netmask: u8,
        destination: Option<Ipv4Addr>,
    ) -> Result<Self> {
        let device = DeviceBuilder::new()
            .name(name)
            .ipv4(address, netmask, destination)
            // TODO: Enable multi_queue when platform supports it
            // .multi_queue(true)
            .build_sync()
            .map_err(std::io::Error::other)?;

        let actual_name = device.name()?;

        Ok(TunDevice {
            device: Arc::new(device),
            name: actual_name,
            interrupt_event: Arc::new(InterruptEvent::new()?),
        })
    }

    /// Create a new TUN device with IPv6 configuration
    pub fn new_with_ipv6(name: &str, address: Ipv6Addr, prefix: u8) -> Result<Self> {
        let device = DeviceBuilder::new()
            .name(name)
            .ipv6(address, prefix)
            // TODO: Enable multi_queue when platform supports it
            // .multi_queue(true)
            .build_sync()
            .map_err(std::io::Error::other)?;

        let actual_name = device.name()?;

        Ok(TunDevice {
            device: Arc::new(device),
            name: actual_name,
            interrupt_event: Arc::new(InterruptEvent::new()?),
        })
    }

    /// Create a new TUN device with custom MTU
    pub fn new_with_mtu(name: &str, mtu: u16) -> Result<Self> {
        let device = DeviceBuilder::new()
            .name(name)
            .mtu(mtu)
            // TODO: Enable multi_queue when platform supports it
            // .multi_queue(true)
            .build_sync()
            .map_err(std::io::Error::other)?;

        let actual_name = device.name()?;

        Ok(TunDevice {
            device: Arc::new(device),
            name: actual_name,
            interrupt_event: Arc::new(InterruptEvent::new()?),
        })
    }

    /// Create a new queue for multi-queue support (requires multi-queue to be enabled)
    pub fn new_queue(&self) -> Result<TunDevice> {
        // Note: try_clone() method might not be available on all platforms
        // For now, we create a copy by cloning the Arc
        let new_device = self.device.clone();
        Ok(TunDevice {
            device: new_device,
            name: self.name.clone(),
            interrupt_event: Arc::clone(&self.interrupt_event),
        })
    }

    /// Trigger the interrupt event, wake up the thread that is waiting on read()
    pub fn trigger_interrupt(&self) -> Result<()> {
        self.interrupt_event.reset()?;
        self.interrupt_event.trigger()?;
        Ok(())
    }

    /// Get the interrupt event
    pub fn interrupt_event(&self) -> Arc<InterruptEvent> {
        Arc::clone(&self.interrupt_event)
    }

    /// Get the name of the TUN device
    pub fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    /// Set the device to non-blocking mode
    pub fn set_non_blocking(self) -> Result<Self> {
        self.device.set_nonblocking(true)?;
        Ok(self)
    }

    /// Get the current MTU of the device
    pub fn mtu(&self) -> Result<usize> {
        Ok(self.device.mtu()? as usize)
    }

    /// Configure IPv4 address for the device
    pub fn set_ipv4_address(
        &self,
        address: Ipv4Addr,
        netmask: u8,
        destination: Option<Ipv4Addr>,
    ) -> Result<()> {
        self.device
            .set_network_address(address, netmask, destination)?;
        Ok(())
    }

    /// Add an IPv6 address to the device
    pub fn add_ipv6_address(&self, address: Ipv6Addr, prefix: u8) -> Result<()> {
        self.device.add_address_v6(address, prefix)?;
        Ok(())
    }

    /// Remove an IP address from the device
    pub fn remove_address(&self, address: IpAddr) -> Result<()> {
        self.device.remove_address(address)?;
        Ok(())
    }

    /// Get all IP addresses associated with the device
    pub fn addresses(&self) -> Result<Vec<IpAddr>> {
        self.device.addresses()
    }

    /// Set the MTU (Maximum Transmission Unit) for the device
    pub fn set_mtu(&self, mtu: u16) -> Result<()> {
        self.device.set_mtu(mtu)?;
        Ok(())
    }

    /// Set the MAC address for the device (TAP devices only)
    pub fn set_mac_address(&self, mac: [u8; 6]) -> Result<()> {
        self.device.set_mac_address(mac)?;
        Ok(())
    }

    /// Get the MAC address of the device (TAP devices only)
    pub fn mac_address(&self) -> Result<[u8; 6]> {
        self.device.mac_address()
    }

    /// Enable or disable the device
    pub fn set_enabled(&self, enabled: bool) -> Result<()> {
        self.device.enabled(enabled)?;
        Ok(())
    }

    /// Get the interface index
    pub fn if_index(&self) -> Result<u32> {
        self.device.if_index()
    }
}

impl Read for TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.device.recv_intr(buf, &self.interrupt_event)
    }
}

impl Write for TunDevice {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.device.send_intr(buf, &self.interrupt_event)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for &TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.device.recv_intr(buf, &self.interrupt_event)
    }
}

impl Write for &TunDevice {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.device.send_intr(buf, &self.interrupt_event)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
