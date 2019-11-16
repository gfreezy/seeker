//! hermes documentation
#![allow(clippy::unreadable_literal)]
use async_std::task;
use std::env;
use std::net::Ipv4Addr;

use getopts::Options;

use hermesdns::DnsNetworkClient;
use hermesdns::DnsUdpServer;
use hermesdns::ForwardingDnsResolver;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag(
        "a",
        "authority",
        "disable support for recursive lookups, and serve only local zones",
    );
    opts.optopt(
        "f",
        "forward",
        "forward replies to specified dns server",
        "SERVER",
    );

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    if opt_matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    let mut dns_host = "".to_string();
    if opt_matches.opt_present("f") {
        match opt_matches
            .opt_str("f")
            .and_then(|x| x.parse::<Ipv4Addr>().ok())
        {
            Some(ip) => {
                println!("Running as forwarder");
                dns_host = ip.to_string();
            }
            None => {
                println!("Forward parameter must be a valid Ipv4 address");
                return;
            }
        }
    }

    let allow_recursive = !opt_matches.opt_present("a");

    task::block_on(async {
        let resolver = Box::new(
            ForwardingDnsResolver::new(
                (dns_host, 53),
                allow_recursive,
                Box::new(DnsNetworkClient::new(0).await),
            )
            .await,
        );
        let listen = "0.0.0.0:53";

        println!("Listening on {}", listen);

        // Start DNS servers
        let udp_server = DnsUdpServer::new(listen.to_string(), resolver).await;
        udp_server.run_server().await
    })
}
