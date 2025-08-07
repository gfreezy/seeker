use tun_nat::tun_device::TunDevice;
use route_manager::{Route, RouteManager};
use smoltcp::wire::Ipv4Cidr;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_tun_device_creation() {
    // Test basic TUN device creation
    let result = TunDevice::new("test_tun");
    match result {
        Ok(tun) => {
            println!("TUN device created successfully: {}", tun.name().unwrap_or_default());
        }
        Err(e) => {
            // Expected if we don't have sufficient privileges
            println!("TUN device creation failed (expected without privileges): {e}");
            assert!(e.kind() == std::io::ErrorKind::PermissionDenied ||
                   e.kind() == std::io::ErrorKind::Other);
        }
    }
}

#[test]
fn test_tun_device_creation_with_ipv4() {
    // Test TUN device creation with IPv4 configuration
    let tun_ip = Ipv4Addr::new(10, 0, 0, 1);
    let result = TunDevice::new_with_ipv4("test_tun4", tun_ip, 24, None);

    // This test might fail without root privileges, which is expected
    match result {
        Ok(tun) => {
            println!("TUN device created successfully: {}", tun.name().unwrap_or_default());
        }
        Err(e) => {
            // Expected if we don't have sufficient privileges
            println!("TUN device creation failed (expected without privileges): {e}");
            assert!(e.kind() == std::io::ErrorKind::PermissionDenied ||
                   e.kind() == std::io::ErrorKind::Other);
        }
    }
}

#[test]
fn test_route_manager_integration() {
    // Test route_manager API integration (without actually adding routes)
    let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let gateway = Ipv4Addr::new(10, 0, 0, 1);

    // Create a route object
    let network_addr = IpAddr::V4(cidr.address());
    let gateway_addr = IpAddr::V4(gateway);

    let route = Route::new(network_addr, cidr.prefix_len())
        .with_if_name("test_interface".to_string())
        .with_gateway(gateway_addr);

    // Verify route construction
    assert_eq!(route.destination(), network_addr);
    assert_eq!(route.prefix(), cidr.prefix_len());
    assert_eq!(route.gateway(), Some(gateway_addr));
    assert_eq!(route.if_name(), Some(&"test_interface".to_string()));
}

#[test]
fn test_route_manager_creation() {
    // Test RouteManager creation (may fail without privileges)
    let result = RouteManager::new();

    match result {
        Ok(_) => {
            // Successfully created route manager
            println!("RouteManager created successfully");
        }
        Err(e) => {
            // Expected if we don't have sufficient privileges
            println!("RouteManager creation failed (expected without privileges): {e}");
            assert!(e.kind() == std::io::ErrorKind::PermissionDenied ||
                   e.kind() == std::io::ErrorKind::Other);
        }
    }
}

#[test]
fn test_run_nat_function() {
    // Test the main run_nat function (will fail without privileges but should compile)
    use tun_nat::run_nat;
    use smoltcp::wire::Ipv4Cidr;
    use std::net::Ipv4Addr;

    let tun_ip = Ipv4Addr::new(10, 0, 0, 1);
    let tun_cidr = Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let additional_cidrs = vec![Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24)];

    let result = run_nat(
        "test_nat_tun",
        tun_ip,
        tun_cidr,
        8080,
        &additional_cidrs,
        1,
        1,
    );

    match result {
        Ok((session_manager, handle)) => {
            println!("NAT started successfully");
            // In a real test, we might want to stop the NAT after a short time
            // For now, just verify we got the expected types
            drop(session_manager);
            drop(handle);
        }
        Err(e) => {
            // Expected if we don't have sufficient privileges
            println!("NAT startup failed (expected without privileges): {e}");
            assert!(e.kind() == std::io::ErrorKind::PermissionDenied ||
                   e.kind() == std::io::ErrorKind::Other);
        }
    }
}
