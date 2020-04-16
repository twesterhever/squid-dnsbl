#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

""" dnsbl-ip [.py]

Squid helper for checking any domain or IP against a specified RBL.
Domains are read from STDIN and checked if they are valid. If
so, a DNS query is performed for any resolved IP address and its
result enumerated. IP adresses are checked agains RBL directly.

In case multiple RBL URIs are given as command line arguments,
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
RBL_MAP_FILE = "/opt/squid-dnsbl/rblmap"
RBL_MAP = {}

# Should failing RFC 5782 (section 5) tests result in permanent BH
# responses (fail close behaviour)? If set to False, an error message
# is logged and the scripts continues to send DNS queries to the RBL.
#
# WARNING: You are strongly advised not to set this to False! Doing
# so is a security risk, as an attacker or outage might render the RBL
# FQDN permanently unusable, provoking a silent fail open behaviour.
RETURN_BH_ON_FAILED_RFC_TEST = True


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

if os.path.isfile(RBL_MAP_FILE):
    with open(RBL_MAP_FILE, "r") as mapfile:
        mapcontent = mapfile.read().strip()

    # JSON module is needed for loading the dictionary representation into
    # a dictionary...
    import json

    RBL_MAP = json.loads(mapcontent)
    LOGIT.debug("Successfully read RBL map dictionary from %s", RBL_MAP_FILE)


RBL_DOMAIN = []


def is_valid_domain(chkdomain: str):
    """ Function call: is_valid_domain(domain name)

    Checks if given domain is valid, i.e. does not contain any
    unspecified characters. It returns True if a domain was valid,
    and False if not."""

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


def build_reverse_ip(ipaddr):
    """ Function call: build_reverse_ip(IP address)

    This function takes an IPv4 or IPv6 address, and converts it so
    a RBL query can performed with. The full DNS query string is then
    returned back."""

    addr = ipaddress.ip_address(ipaddr)

    if addr.version == 6 or addr.version == 4:
        # In this case, we are dealing with an IP address
        rev = '.'.join(addr.reverse_pointer.split('.')[:-2])
        return rev

    # In this case, we are dealing with a martian
    return None


def resolve_addresses(domain: str):
    """ Function call: resolve_address(domain)

    This function takes a domain and enumerates all IPv4 and IPv6
    records for it. They are returned as an array."""

    # Check if this is a valid domain...
    if not is_valid_domain(domain):
        return None

    # Enumerate IPv6 addresses...
    ip6a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'AAAA'):
            ip6a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    # Enumerate IPv4 addresses...
    ip4a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'A'):
            ip4a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    # Assemble all IP addresses and return them back
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

    # Test if 127.0.0.1 is not listed
    try:
        RESOLVER.query((build_reverse_ip("127.0.0.1") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.debug("RBL '%s' is not listing testpoint address 127.0.0.1 - good", rbltdomain)
    else:
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it lists 127.0.0.1", rbltdomain)
        return False

    # Test if 127.0.0.2 is listed
    try:
        RESOLVER.query((build_reverse_ip("127.0.0.2") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it does not list 127.0.0.2", rbltdomain)
        return False
    else:
        LOGIT.debug("RBL '%s' is listing testpoint address 127.0.0.2 - good", rbltdomain)

    LOGIT.info("RBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", rbltdomain)
    return True


# Test if DNSBL URI is a valid domain...
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
        RBL_DOMAIN.append(tdomain.strip(".") + ".")

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.lifetime = 5

# Test if specified RBLs work correctly (according to RFC 5782 [section 5])...
PASSED_RFC_TEST = True
for trbl in RBL_DOMAIN:
    if not test_rbl_rfc5782(trbl):
        # In this case, an RBL has failed the test...
        LOGIT.warning("RFC 5782 (section 5) test for RBL '%s' failed", trbl)
        PASSED_RFC_TEST = False

# Depending on the configuration at the beginning of this script, further
# queries will or will not result in BH every time. Adjust log messages...
if not PASSED_RFC_TEST and RETURN_BH_ON_FAILED_RFC_TEST:
    LOGIT.error("Aborting due to failed RFC 5782 (section 5) test for RBL")
elif not PASSED_RFC_TEST:
    LOGIT.warning("There were failed RFC 5782 (section 5) RBL tests. Possible fail open provocation, resuming normal operation, you have been warned...")
    PASSED_RFC_TEST = True
else:
    LOGIT.info("All specified RBLs are operational and passed RFC 5782 (section 5) test - excellent. Waiting for input...")

# Read domain names or IP addresses from STDIN in a while loop, and do RBL lookups
# for every valid domin or IP address. In case it is not listed in RBL, ERR is returned.
# BH is returned if input was invalid. Otherwise, return string is OK.
while True:
    try:
        QSTRING = str(sys.stdin.readline().rstrip().split()[0])
    except KeyboardInterrupt:
        sys.exit(127)

    # Abort if query string was empty (no STDIN input received)
    if not QSTRING:
        break

    # Immediately return BH if configuration requires to do so...
    if RETURN_BH_ON_FAILED_RFC_TEST and not PASSED_RFC_TEST:
        print("BH")
        continue

    # Enumerate whether query string is a domain or an IP address...
    try:
        IPS = [ipaddress.ip_address(QSTRING)]
    except (ValueError, AttributeError):
        # In this case, we are probably dealing with a domain
        IPS = resolve_addresses(QSTRING.strip(".") + ".")

    # Check if we have some IP addresses to lookup for...
    if not IPS:
        # ... if not, we'll return ERR instead of BH, since the latter one causes Squid
        # to display "permission denied" messages to the client, which is confusing.
        #
        # ERR is considered to be safe here, as Squid won't be able to establish a
        # connection anyway, no matter whether the destination is blacklisted or not,
        # provided both Squid and this script use the same DNS resolver.
        LOGIT.info("Unable to resolve queried destination '%s', returning ERR...", QSTRING)
        print("ERR")
    else:
        # Query each IP address against RBL and enumerate output...
        qfailed = False

        for udomain in RBL_DOMAIN:
            for idx, qip in enumerate(IPS):
                try:
                    answer = RESOLVER.query((build_reverse_ip(qip) + "." + udomain), 'A')
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

                        # If a RBL map file is present, the corresponding key to each DNS reply
                        # for this RBL is enumerated and passed to Squid via additional keywords...
                        if RBL_MAP:
                            try:
                                rblmapoutput += RBL_MAP[udomain.strip(".")][rdata] + ", "
                            except KeyError:
                                pass

                    LOGIT.warning("RBL hit on '%s.%s' with response '%s' (queried destination: '%s')",
                                  build_reverse_ip(qip), udomain, responses.strip(), QSTRING)

                    if RBL_MAP:
                        rblmapoutput = rblmapoutput.strip(", ")
                        rblmapoutput += "\""
                        print("OK", rblmapoutput)
                    else:
                        print("OK")
                    break
            else:
                continue
            break

        if qfailed:
            print("ERR")

# EOF
