#!/usr/local/bin/python3 -u
# -*- coding: utf-8 -*-

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
import os.path
import logging
import logging.handlers
import dns.resolver

# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('squid-dnsbl-helper')
LOGIT.setLevel(logging.INFO)

if os.path.islink("/dev/log"):
    HANDLER = logging.handlers.SysLogHandler(address="/dev/log")
else:
    HANDLER = logging.StreamHandler(stream=sys.stderr)

LOGIT.addHandler(HANDLER)

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
    ip6a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'AAAA'):
            ip6a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass

    # enumerate IPv4 addresses...
    ip4a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'A'):
            ip4a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass

    # assemble all IP addresses and return them back
    ips = ip6a + ip4a
    return ips


def test_rbl_rfc5782(rbltdomain: str):
    """ Function call: test_rbl_rfc5782(RBL address)

    This function tests if an RBL works properly according to RFC 5782 (section 5).
    It specifies an RBL must not list 127.0.0.1, and must list
    127.0.0.2 for testing purposes.

    Since IPv6 listings are comperatively rare at the time of writing,
    IPv6 related tests are omitted here.

    In case of success, a boolean True is returned, and False otherwise."""

    # test if 127.0.0.1 is not listed
    try:
        RESOLVER.query((build_reverse_ip("127.0.0.1") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.debug("RBL '%s' is not listing testpoint address 127.0.0.1 - good", rbltdomain)
    else:
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it lists 127.0.0.1", rbltdomain)
        return False

    # test if 127.0.0.2 is listed
    try:
        RESOLVER.query((build_reverse_ip("127.0.0.2") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it does not list 127.0.0.2", rbltdomain)
        return False
    else:
        LOGIT.debug("RBL '%s' is listing testpoint address 127.0.0.2 - good", rbltdomain)

    LOGIT.info("RBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", rbltdomain)
    return True


# test if DNSBL URI is a valid domain...
try:
    if not sys.argv[1]:
        print("BH")
        sys.exit(127)
except IndexError:
    print("Usage: " + sys.argv[0] + " RBL1 RBL2 RBLn")
    sys.exit(127)

for tdomain in sys.argv[1:]:
    if not is_valid_domain(tdomain):
        print("BH")
        sys.exit(127)
    else:
        RBLDOMAIN.append(tdomain.strip(".") + ".")

# set up resolver object
RESOLVER = dns.resolver.Resolver()

# set timeout for resolving
RESOLVER.timeout = 2

# test if specified RBLs work correctly (according to RFC 5782 [section 5])...
for trbl in RBLDOMAIN:
    if not test_rbl_rfc5782(trbl):
        # in this case, an RBL has failed the test...
        LOGIT.error("Aborting due to failed RFC 5782 (section 5) test for RBL '%s'", trbl)
        print("Aborting due to failed RFC 5782 (section 5) test for RBL '" + trbl + "'")
        sys.exit(127)

LOGIT.info("All specified RBLs are operational and passed RFC 5782 (section 5) test - excellent. Waiting for input...")
# read domain names or IP addresses from STDIN in a while loop, and do RBL lookups
# for every valid domin or IP address. In case it is not listed in RBL, ERR is returned.
# BH is returned if input was invalid. Otherwise, return string is OK.
while True:
    try:
        QSTRING = str(sys.stdin.readline().rstrip().split()[0])
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
        print("BH")
    else:
        # query each IP address against RBL and enumerate output...
        qfailed = False

        for udomain in RBLDOMAIN:
            for idx, qip in enumerate(IPS):
                try:
                    answer = RESOLVER.query((build_reverse_ip(qip) + "." + udomain), 'A')
                except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
                    qfailed = True
                else:
                    print("OK")
                    qfailed = False

                    # concatenate responses and log them...
                    responses = ""
                    for rdata in answer:
                        responses = responses + str(rdata) + " "

                    LOGIT.warning("RBL hit on '%s.%s' with response '%s'",
                                  build_reverse_ip(qip), udomain, responses.strip())
                    break
            else:
                continue
            break

        if qfailed:
            print("ERR")

# EOF
