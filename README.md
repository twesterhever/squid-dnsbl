# Squid helpers for querying domains and IPs against DNSBLs

The [http://www.squid-cache.org/](Squid) proxy software is widely
used, and so is its ability to introduce access limits, i.e.
by only allowing traffic to well-known ports.

While Squid is able to handle file based blocklists by taking
advantage of [http://squidguard.org/](SquidGuard), the usage
of DNSBLs has never been that easy. There is
[http://squidguard.org/Downloads/Contrib/squidGuard-1.4-dnsbl.patch](some patch available)
which adds this feature, but it did not seem to made it into
many distribution packages.

Worse, SquidGuard does not support querying resolved IP
addresses of a domain against RBLs. Since cyber criminals
tend to host multiple domains on the same IP address, this
might be useful.

This repository aims to close this gap by providing to Python 3.x
based scripts which can be accessed by Squid as external helpers.

## dnsbl.py

## dnsbl-ip.py

## Example Squid configuration

