#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

""" dnsbl [.py]

Squid helper script for querying domains against a given DNSBL
such as Spamhaus DBL. IP addresses are handled, but will most
likely not result in any useful query (see dnsbl-ip.py for
further details on this).

In case multiple DNSBL URIs are given as command line arguments,
the script uses all of them. Additional blacklist information is
passed via keywords, e.g. for using it in custom built error pages. """

# Import needed packages
import ipaddress
import re
import sys
import os.path
import logging
import logging.handlers
import dns.resolver

# *** Define constants and settings... ***

# If desired, a mapping of DNS return values to human readable
# strings can be specified here. This may be used for displaying
# the blacklist source to users in order to avoid confusion.
#
# Please see the corresponding Squid documentation for further information:
# http://www.squid-cache.org/Doc/config/external_acl_type/
#
# NOTE: This helper stops after first blacklist match. If desired,
# consider building an aggregated RBL with distinct DNS answers
# returned all at once.
URIBL_MAP_FILE = "/opt/squid-dnsbl/uriblmap"
URIBL_MAP = {}

# Should failing RFC 5782 (section 5) tests result in permanent BH
# responses (fail close behaviour)? If set to False, an error message
# is logged and the scripts continues to send DNS queries to the RBL.
#
# WARNING: You are strongly advised not to set this to False! Doing
# so is a security risk, as an attacker or outage might render the RBL
# FQDN permanently unusable, provoking a silent fail open behaviour.
RETURN_BH_ON_FAILED_RFC_TEST = True

# NOTE: While RBLs passing RFC 5782 (section 5) test can be considered operational,
# at least on a very basic level, this is not sufficient for URIBLs as it does
# not detect strict QNAME minimization being in use on the DNS resolver configured.
#
# Strict QNAME minimization, particular in combination with stub-zones, effectively
# renders DNSBLs unusable and cannot be reliably detected by RFC 5782 (section 5)
# tests against URIBLs. You are therefore _strongly_ encouraged not to enable
# strict QNAME minimization.


# Initialise logging (to "/dev/log" - or STDERR if unavailable - for level INFO by default)
LOGIT = logging.getLogger('squid-dnsbl-helper')
LOGIT.setLevel(logging.INFO)

if os.path.islink("/dev/log"):
    HANDLER = logging.handlers.SysLogHandler(address="/dev/log")
else:
    HANDLER = logging.StreamHandler(stream=sys.stderr)
    # There is no additional metadata available when logging to STDERR,
    # so a logging formatter needs to be added here...
    FORMAT = logging.Formatter(fmt="%(asctime)s %(name)s[%(process)d] %(levelname).4s: %(message)s",
                               datefmt="%b %d %H:%M:%S")
    HANDLER.setFormatter(FORMAT)

LOGIT.addHandler(HANDLER)

if os.path.isfile(URIBL_MAP_FILE):
    with open(URIBL_MAP_FILE, "r") as mapfile:
        mapcontent = mapfile.read().strip()

    # JSON module is needed for loading the dictionary representation into
    # a dictionary...
    import json

    URIBL_MAP = json.loads(mapcontent)
    LOGIT.debug("Successfully read URIBL map dictionary from %s", URIBL_MAP_FILE)


URIBL_DOMAIN = []


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

    # Test if chkdomain is an IP address (should not happen here)
    if is_ipaddress(chkdomain):
        return False

    # Allowed characters
    allowedchars = re.compile(r"(?!-)[a-z\d\-\_]{1,63}(?<!-)$", re.IGNORECASE)

    if len(chkdomain) > 255 or "." not in chkdomain:
        # Do not allow domains which are very long or do not contain a dot
        return False

    if chkdomain[-1] == ".":
        # Strip trailing "." if present
        chkdomain = chkdomain[:-1]

    # Check if sublabels are invalid (i.e. are empty, too long or contain
    # invalid characters)
    for sublabel in chkdomain.split("."):
        if not sublabel or not allowedchars.match(sublabel):
            # Sublabel is invalid
            return False

    return True


def test_rbl_rfc5782(uribltdomain: str):
    """ Function call: test_rbl_rfc5782(URIBL address)

    This function tests if an URIBL works properly according to RFC 5782 (section 5).
    It specifies an URIBL must not list "invalid", and must list
    "test" for testing purposes.

    In case of success, a boolean True is returned, and False otherwise."""

    # Test if "invalid" is not listed
    try:
        RESOLVER.query("invalid." + uribltdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.debug("URIBL '%s' is not listing testpoint address 'invalid' - good", uribltdomain)
    else:
        LOGIT.error("URIBL '%s' is violating RFC 5782 (section 5) as it lists 'invalid'", uribltdomain)
        return False

    # Test if "test" is listed
    try:
        RESOLVER.query("test." + uribltdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("URIBL '%s' is violating RFC 5782 (section 5) as it does not list 'test'", uribltdomain)
        return False
    else:
        LOGIT.debug("URIBL '%s' is listing testpoint address 'test' - good", uribltdomain)

    LOGIT.info("URIBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", uribltdomain)
    return True


# Test if DNSBL URI is a valid domain...
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
        URIBL_DOMAIN.append(tdomain.strip(".") + ".")

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.lifetime = 5

# Test if specified URIBLs work correctly (according to RFC 5782 [section 5])...
PASSED_RFC_TEST = True
for turibl in URIBL_DOMAIN:
    if not test_rbl_rfc5782(turibl):
        # in this case, an URIBL has failed the test...
        LOGIT.warning("RFC 5782 (section 5) test for URIBL '%s' failed", turibl)
        PASSED_RFC_TEST = False

# Depending on the configuration at the beginning of this script, further
# queries will or will not result in BH every time. Adjust log messages...
if not PASSED_RFC_TEST and RETURN_BH_ON_FAILED_RFC_TEST:
    LOGIT.error("Aborting due to failed RFC 5782 (section 5) test for URIBL")
elif not PASSED_RFC_TEST:
    LOGIT.warning("There were failed RFC 5782 (section 5) URIBL tests. Possible fail open provocation, resuming normal operation, you have been warned...")
    PASSED_RFC_TEST = True
else:
    LOGIT.info("All specified URIBLs are operational and passed RFC 5782 (section 5) test - excellent. Waiting for input...")

# Read domain names from STDIN in a while loop, and do URIBL lookups
# for every valid domin. In case it is not listed in URIBL, ERR is returned.
# BH is returned if input was invalid. Otherwise, return string is OK.
while True:
    try:
        QUERYDOMAIN = str(sys.stdin.readline().rstrip().split()[0])
    except KeyboardInterrupt:
        sys.exit(127)

    # Abort if domain was empty (no STDIN input received)
    if not QUERYDOMAIN:
        break

    # Immediately return BH if configuration requires to do so...
    if RETURN_BH_ON_FAILED_RFC_TEST and not PASSED_RFC_TEST:
        print("BH")
        continue

    # Check if input is an IP address (we need to return ERR in such
    # cases, as most URIBLs are unable to handle them, and BH will result
    # in blocking direct IP communication)
    if is_ipaddress(QUERYDOMAIN):
        print("ERR")
        continue

    # Check if it is a valid domain
    if not is_valid_domain(QUERYDOMAIN):
        print("BH")
        continue

    # Test if an A record can be found for this domain
    # some exceptions in case of invalid domains (label too long, or empty)
    # are also handled here
    for udomain in URIBL_DOMAIN:
        try:
            answer = RESOLVER.query((QUERYDOMAIN + "." + udomain), 'A')
        except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
            qfailed = True
        else:
            qfailed = False

            # Concatenate responses and log them...
            responses = ""
            rblmapoutput = "blacklist=\""
            for rdata in answer:
                rdata = str(rdata)
                responses = responses + rdata + " "

                # If a URIBL map file is present, the corresponding key to each DNS reply
                # for this URIBL is enumerated and passed to Squid via additional keywords...
                if URIBL_MAP:
                    try:
                        rblmapoutput += URIBL_MAP[udomain.strip(".")][rdata] + ", "
                    except KeyError:
                        pass

                LOGIT.warning("URIBL hit on '%s.%s' with response '%s'",
                              QUERYDOMAIN, udomain, responses.strip())

            if URIBL_MAP:
                uriblmapoutput = uriblmapoutput.strip(", ")
                uriblmapoutput += "\""
                print("OK", uriblmapoutput)
            else:
                print("OK")
            break

    if qfailed:
        print("ERR")

# EOF
