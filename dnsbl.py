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

# Initialise logging (to "/dev/log" for level INFO by default)
LOGIT = logging.getLogger('squid-dnsbl-helper')
LOGIT.setLevel(logging.INFO)

SYSLOGH = logging.handlers.SysLogHandler(address="/dev/log")
LOGIT.addHandler(SYSLOGH)

URIBLDOMAIN = []


def is_ipaddress(chkinput: str):
    """ Function call: is_ipaddress(input)

    Tests if input is an IP address. It returns True if it
    is one (v4/v6 does not matter), and False if not."""

    try:
        ipaddress.ip_address(chkinput)
        return True
    except ValueError:
        return False


def is_valid_domain(chkdomain: str):
    """ Function call: is_valid_domain(domain name)

    Checks if given domain is valid, i.e. does not contain any
    unspecified characters. It returns True if a domain was valid,
    and False if not."""

    # test if chkdomain is an IP address (should not happen here)
    if is_ipaddress(chkdomain):
        return False

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


def test_rbl_rfc5782(uribltdomain: str):
    """ Function call: test_rbl_rfc5782(URIBL address)

    This function tests if an URIBL works properly according to RFC 5782 (section 5).
    It specifies an URIBL must not list "invalid", and must list
    "test" for testing purposes.

    In case of success, a boolean True is returned, and False otherwise."""

    # test if "invalid" is not listed
    try:
        RESOLVER.query("invalid." + uribltdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.debug("URIBL '%s' is not listing testpoint address 'invalid' - good", uribltdomain)
    else:
        LOGIT.error("URIBL '%s' is violating RFC 5782 (section 5) as it lists 'invalid'", uribltdomain)
        return False

    # test if "test" is listed
    try:
        RESOLVER.query("test." + uribltdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("URIBL '%s' is violating RFC 5782 (section 5) as it does not list 'test'", uribltdomain)
        return False
    else:
        LOGIT.debug("URIBL '%s' is listing testpoint address 'test' - good", uribltdomain)

    LOGIT.info("URIBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", uribltdomain)
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

# test if specified URIBLs work correctly (according to RFC 5782 [section 5])...
for turibl in URIBLDOMAIN:
    if not test_rbl_rfc5782(turibl):
        # in this case, an URIBL has failed the test...
        LOGIT.error("Aborting due to failed RFC 5782 (section 5) test for URIBL '%s'", turibl)
        print("Aborting due to failed RFC 5782 (section 5) test for URIBL '" + turibl + "'")
        sys.exit(127)

LOGIT.info("All specified URIBLs are operational and passed RFC 5782 (section 5) test - excellent. Waiting for input...")
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

    # check if input is an IP address (we need to return ERR in such
    # cases, as most URIBLs are unable to handle them, and BH will result
    # in blocking direct IP communication)
    if is_ipaddress(QUERYDOMAIN):
        print("ERR")
        continue

    # check if it is a valid domain
    if not is_valid_domain(QUERYDOMAIN):
        print("BH")
        continue

    # test if an A record can be found for this domain
    # some exceptions in case of invalid domains (label too long, or empty)
    # are also handled here
    for udomain in URIBLDOMAIN:
        try:
            answer = RESOLVER.query((QUERYDOMAIN + "." + udomain), 'A')
        except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
            qfailed = True
        else:
            print("OK")
            qfailed = False

            # concatenate responses and log them...
            responses = ""
            for rdata in answer:
                responses = responses + str(rdata) + " "

            LOGIT.warning("URIBL hit on '%s.%s' with response '%s'",
                          QUERYDOMAIN, udomain, responses.strip())
            break

    if qfailed:
        print("ERR")

# EOF
