#!/usr/local/bin/python3 -u
# -*- coding: utf-8 -*-

""" dnsbl [.py]

Squid helper script for querying domains against a given DNSBL
such as Spamhaus DBL. IP addresses are handled, but will most
likely not result in any useful query (see dnsbl-ip.py for
further details on this).

In case multiple DNSBL URIs are given as command line arguments,
the script uses all of them."""

# Import needed packages
import ipaddress
import re
import sys
import logging
import logging.handlers
import dns.resolver

# Initialise logging (to "/dev/log" for level WARNING by default)
LOGIT = logging.getLogger('squid-dnsbl-helper')
LOGIT.setLevel(logging.WARNING)

SYSLOGH = logging.handlers.SysLogHandler(address="/dev/log")
LOGIT.addHandler(SYSLOGH)

URIBLDOMAIN = []


def is_valid_domain(chkdomain: str):
    """ Function call: is_valid_domain(domain name)

    Checks if given domain is valid, i.e. does not contain any
    unspecified characters. It returns True if a domain was valid,
    and False if not."""

    # test if chkdomain is an IP address (we will return ERR in
    # such cases, as most URIBLs are unable to handle them)
    try:
        ipaddress.ip_address(chkdomain)
        return False
    except ValueError:
        pass

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


# test if DNSBL URI is a valid domain...
try:
    if not sys.argv[1]:
        print("BH")
        sys.exit(127)
except IndexError:
    print("Usage: " + sys.argv[0] + " URIBL1 URIBL2 URIBLn")
    sys.exit(127)

for tdomain in sys.argv[1:]:
    if not is_valid_domain(tdomain):
        print("BH")
        sys.exit(127)
    else:
        URIBLDOMAIN.append(tdomain.strip(".") + ".")

# set up resolver object
RESOLVER = dns.resolver.Resolver()

# set timeout for resolving
RESOLVER.timeout = 2

# read domain names from STDIN in a while loop, and do URIBL lookups
# for every valid domin. In case it is not listed in URIBL, ERR is returned.
# BH is returned if input was invalid. Otherwise, return string is OK.
while True:
    try:
        QUERYDOMAIN = str(sys.stdin.readline().rstrip().split()[0])
    except KeyboardInterrupt:
        sys.exit(127)

    # abort if domain was empty (no STDIN input received)
    if not QUERYDOMAIN:
        break

    # check if it is a valid domain
    if not is_valid_domain(QUERYDOMAIN):
        print("BH")
        continue

    # test if an A record can be found for this domain
    # some exceptions in case of invalid domains (label too long, or empty)
    # are also handled here
    for udomain in URIBLDOMAIN:
        try:
            RESOLVER.query((QUERYDOMAIN + "." + udomain), 'A')
        except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
            qfailed = True
        else:
            print("OK")
            qfailed = False
            LOGIT.warning("URIBL hit on %s.%s", QUERYDOMAIN, udomain)
            break

    if qfailed:
        print("ERR")

# EOF
