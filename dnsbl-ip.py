#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

""" dnsbl-ip [.py]

Squid helper for checking any domain or IP against a specified RBL.
Domains are read from STDIN and checked if they are valid. If
so, a DNS query is performed for any resolved IP address and its
result enumerated. IP adresses are checked agains RBL directly.

In case multiple RBL URIs are given as command line arguments,
the script uses all of them."""

# Import needed packages
import ipaddress
import re
import sys
import dns.resolver

RBLDOMAIN = []


def is_valid_domain(chkdomain: str):
    """ Function call: is_valid_domain(domain name)

    Checks if given domain is valid, i.e. does not contain any
    unspecified characters. It returns True if a domain was valid,
    and False if not."""

    # allowed characters
    allowedchars = re.compile(r"(?!-)[a-z\d\-\_]{1,63}(?<!-)$", re.IGNORECASE)

    if len(chkdomain) > 255 or "." not in chkdomain:
        # do not allow domains which are very long or do not contain a dot
        return False

    if chkdomain[-1] == ".":
        # strip trailing "." if present
        chkdomain = chkdomain[:-1]

    # check if sublabels are invalid (i.e. are empty, too long or contain
    # invalid characters)
    for sublabel in chkdomain.split("."):
        if not sublabel or not allowedchars.match(sublabel):
            # sublabel is invalid
            return False

    return True


def build_reverse_ip(ipaddr):
    """ Function call: build_reverse_ip(IP address)

    This function takes an IPv4 or IPv6 address, and converts it so
    a RBL query can performed with. The full DNS query string is then
    returned back."""

    addr = ipaddress.ip_address(ipaddr)

    if addr.version == 6 or addr.version == 4:
        # in this case, we are dealing with an IP address
        rev = '.'.join(addr.reverse_pointer.split('.')[:-2])
        return rev
    else:
        # in this case, we are dealing with a martian
        return None


def resolve_addresses(domain: str):
    """ Function call: resolve_address(domain)

    This function takes a domain and enumerates all IPv4 and IPv6
    records for it. They are returned as an array."""

    # check if this is a valid domain...
    if not is_valid_domain(domain):
        return None

    # enumerate IPv6 addresses...
    try:
        ip6a = str(RESOLVER.query(domain, 'AAAA')[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        ip6a = ""

    # enumerate IPv4 addresses...
    try:
        ip4a = str(RESOLVER.query(domain, 'A')[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        ip4a = ""

    # assemble all IP addresses and return them back
    ips = (ip6a + " " + ip4a).split()
    return ips


# test if DNSBL URI is a valid domain...
if not sys.argv[1]:
    print("ERR")
    sys.exit(127)

for tdomain in sys.argv[1:]:
    if not is_valid_domain(tdomain):
        print("ERR")
        sys.exit(127)
    else:
        RBLDOMAIN.append(tdomain + ".")

# set up resolver object
RESOLVER = dns.resolver.Resolver()

# set timeout for resolving
RESOLVER.timeout = 2

# read domain names or IP addresses from STDIN in a while loop, and do RBL lookups
# for every valid domin or IP address. In case it is not listed in RBL or was not
# a valid domain name, ERR is returned. Otherwise, it's OK.
while True:
    try:
        QSTRING = str(sys.stdin.readline().rstrip())
    except KeyboardInterrupt:
        sys.exit(127)

    # abort if query string was empty (no STDIN input received)
    if not QSTRING:
        break

    # enumerate whether query string is a domain or an IP address...
    try:
        IPS = [ipaddress.ip_address(QSTRING)]
    except (ValueError, AttributeError):
        # in this case, we are probably dealing with a domain
        IPS = resolve_addresses(QSTRING)

    # check if we have some IP addresses to lookup for...
    if not IPS:
        print("ERR")
    else:
        # query each IP address against RBL and enumerate output...
        qfailed = False

        for udomain in RBLDOMAIN:
            for idx, qip in enumerate(IPS):
                try:
                    RESOLVER.query((build_reverse_ip(qip) + "." + udomain), 'A')
                except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
                    qfailed = True
                else:
                    print("OK")
                    qfailed = False
                    break

        if qfailed:
            print("ERR")

# EOF
