Hermes DNS server
=================

Hermes is a compact DNS server in safe rust. It provides:

 * Quick and easy configuration through a few select command line parameters.
 * The ability to recursively resolve directly using the Internet root servers
   out of the box, to spare you from trusting anybody else's name servers.
 * Alternatively, use it in forwarding mode to pass your queries onto a DNS
   server of your choice.
 * The ability to act as an authoritative server for your own zones.
 * A compact API with dual support for HTML and JSON media types across the
   same endpoints, for easy administration of zones and caching behavior.

Why? As a developer, I usually run many hosts and docker containers on my own
machine and assign them names using hosts.txt. I wanted a more convenient way
of accomplishing that. Additionally, I like having some insight into the
network traffic that passes in and out of my machine and network, and
monitoring the DNS layer for anomalies is actually a rather convenient way of
doing so.

Command Line Options
--------------------

This is the result of running `hermes -h`

    Usage: hermes [options]

    Options:
        -h, --help          print this help menu
        -a, --authority     disable support for recursive lookups, and serve only
                            local zones
        -f, --forward SERVER
                            forward replies to specified dns server

Changes From Original Repo
-------
1. Use async/await with `async-std` and `async-trait`
2. Remove dns over tcp

Thanks
-------
Originated from https://github.com/EmilHernvall/hermes.
Thanks to Emil Hernvall <emil@c0la.se>
