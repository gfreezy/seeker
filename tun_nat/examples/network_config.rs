// Example showing how to use TunDevice with tun-rs network configuration methods
use std::net::{Ipv4Addr, Ipv6Addr};
use tun_nat::tun_device::TunDevice;

fn main() -> std::io::Result<()> {
    // Example 1: Create a TUN device and configure IPv4 address
    println!("=== Example 1: Basic TUN device with IPv4 configuration ===");
    let tun = TunDevice::new("tun_test")?;

    // Configure IPv4 address using tun-rs methods
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    let netmask = 24;
    tun.set_ipv4_address(ip, netmask, None)?;

    println!("Created TUN device: {}", tun.name()?);
    println!("MTU: {}", tun.mtu()?);
    println!("Addresses: {:?}", tun.addresses()?);

    // Example 2: Create TUN device with IPv4 configuration in one step
    println!("\n=== Example 2: TUN device with pre-configured IPv4 ===");
    let tun_ipv4 = TunDevice::new_with_ipv4(
        "tun_ipv4",
        Ipv4Addr::new(192, 168, 1, 1),
        24,
        None
    )?;

    println!("Created IPv4 TUN device: {}", tun_ipv4.name()?);
    println!("Addresses: {:?}", tun_ipv4.addresses()?);

    // Example 3: Create TUN device with IPv6 configuration
    println!("\n=== Example 3: TUN device with IPv6 configuration ===");
    let tun_ipv6 = TunDevice::new_with_ipv6(
        "tun_ipv6",
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        64
    )?;

    println!("Created IPv6 TUN device: {}", tun_ipv6.name()?);
    println!("Addresses: {:?}", tun_ipv6.addresses()?);

    // Example 4: Create TUN device with custom MTU
    println!("\n=== Example 4: TUN device with custom MTU ===");
    let tun_mtu = TunDevice::new_with_mtu("tun_mtu", 1280)?;

    println!("Created TUN device with custom MTU: {}", tun_mtu.name()?);
    println!("MTU: {}", tun_mtu.mtu()?);

    // Example 5: Runtime network configuration
    println!("\n=== Example 5: Runtime network configuration ===");
    let tun_runtime = TunDevice::new("tun_runtime")?;

    // Set MTU
    tun_runtime.set_mtu(1400)?;
    println!("Set MTU to: {}", tun_runtime.mtu()?);

    // Add IPv6 address
    tun_runtime.add_ipv6_address(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        64
    )?;

    // Enable the device
    tun_runtime.set_enabled(true)?;

    println!("Runtime configured TUN device: {}", tun_runtime.name()?);
    println!("Interface index: {}", tun_runtime.if_index()?);
    println!("Final addresses: {:?}", tun_runtime.addresses()?);

    println!("\n=== All examples completed successfully! ===");

    Ok(())
}
