#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

""" dnsbl [.py]

Squid helper script for querying domains against a given DNSBL
such as Spamhaus DBL. IP addresses are handled as well, but will
most likely not result in any useful queries (see dnsbl-ip.py for
further details on this).

Settings are read from the configuration file path supplied as a
command line argument. """

# Import needed packages
import configparser
import ipaddress
import logging
import logging.handlers
import os
import re
import sys
import concurrent.futures
from getpass import getuser
import dns.resolver


if getuser() == "root" or os.getuid() == 0:
    print("For security purposes, this script must not be executed as root!")
    sys.exit(127)

try:
    CFILE = sys.argv[1]
except IndexError:
    print("Usage: " + sys.argv[0] + " [path to configuration file]")
    sys.exit(127)

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


def query_uribl(config: dict, uribldomain: tuple, querydomain: str):
    """ Function call: query_uribl(ConfigParser object,
                                   URIBL domain tuple,
                                   FQDN to query)

    This function looks up the given FQDN addresses against the URIBL. It returns a tuple
    of a Boolean indiciating whether or not the FQDN address was listed (or None in case
    the query failed), and a string containing reply map information (if configured),
    being empty otherwise.
    """

    returnstate = None
    uriblmapoutput = ""

    try:
        answer = RESOLVER.resolve((querydomain + "." + uribldomain[1]), "A")
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        returnstate = False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("URIBL '%s' failed to answer query for '%s' within %s seconds, returning 'BH'",
                      uribldomain[1], querydomain, RESOLVER.lifetime)
    else:
        returnstate = True

        # Concatenate responses and log them...
        responses = ""

        for rdata in answer:
            rdata = str(rdata)
            responses = responses + rdata + " "

            # If a URIBL map file is present, the corresponding key to each DNS reply
            # for this URIBL is enumerated and passed to Squid via additional keywords...
            if config.getboolean("GENERAL", "USE_REPLYMAP"):
                try:
                    uriblmapoutput += config[uribldomain[0]][rdata] + " (" + querydomain + "), "
                except KeyError:
                    LOGIT.info("replymap is active, but configuration file does not contain data for %s (%s)",
                               uribldomain[0], rdata)
                    uriblmapoutput = "N/A "

        LOGIT.warning("URIBL hit on '%s.%s' with response '%s'",
                      querydomain, uribldomain[1], responses.strip())

    return (returnstate, uriblmapoutput)


def test_rbl_rfc5782(uribltdomain: str):
    """ Function call: test_rbl_rfc5782(URIBL address)

    This function tests if an URIBL works properly according to RFC 5782 (section 5).
    It specifies an URIBL must not list "invalid", and must list
    "test" for testing purposes.

    In case of success, a boolean True is returned, and False otherwise."""

    # Test if "invalid" is not listed
    try:
        RESOLVER.resolve("invalid." + uribltdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.debug("URIBL '%s' is not listing testpoint address 'invalid' - good", uribltdomain)
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("URIBL '%s' failed to answer RFC 5782 (section 5) test query for 'invalid' within %s seconds",
                      uribltdomain, RESOLVER.lifetime)
        return False
    else:
        LOGIT.error("URIBL '%s' is violating RFC 5782 (section 5) as it lists 'invalid'", uribltdomain)
        return False

    # Test if "test" is listed
    try:
        RESOLVER.resolve("test." + uribltdomain, 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("URIBL '%s' is violating RFC 5782 (section 5) as it does not list 'test'", uribltdomain)
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("URIBL '%s' failed to answer RFC 5782 (section 5) test query for 'test' within %s seconds",
                      uribltdomain, RESOLVER.lifetime)
        return False
    else:
        LOGIT.debug("URIBL '%s' is listing testpoint address 'test' - good", uribltdomain)

    LOGIT.debug("URIBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", uribltdomain)
    return True


def test_all_uribls(uribl_domains: list):
    """ Function call: test_all_uribls(list of URIBLs enabled)

    Abstraction layer function for performing RFC 5782 (section 5) tests for all
    URIBLs configured and enabled. Returns True if all of them pass these tests, and
    False otherwise.
    """

    for single_uribl in uribl_domains:
        if not test_rbl_rfc5782(single_uribl[1]):
            # in this case, an URIBL has failed the test...
            LOGIT.warning("RFC 5782 (section 5) test for URIBL '%s' failed", single_uribl[1])
            return False

    return True


if os.path.isfile(CFILE) and not os.path.islink(CFILE):
    LOGIT.debug("Attempting to read configuration from '%s' ...", CFILE)

    if os.access(CFILE, os.W_OK) or os.access(CFILE, os.X_OK):
        LOGIT.error("Supplied configuration file '%s' is writeable or executable, aborting", CFILE)
        print("BH")
        sys.exit(127)

    config = configparser.ConfigParser()

    with open(CFILE, "r") as fptr:
        config.read_file(fptr)

    LOGIT.debug("Read configuration from '%s', performing sanity tests...", CFILE)

    # Attempt to read mandatory configuration parameters and see if they contain
    # useful values, if possible to determine.
    try:
        if config["GENERAL"]["LOGLEVEL"].upper() not in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            raise ValueError("log level configuration invalid")

        if config.getint("GENERAL", "RESOLVER_TIMEOUT") not in range(2, 20):
            raise ValueError("resolver timeout configured out of bounds")

        for singleckey in ["RETURN_BH_ON_FAILED_RFC_TEST",
                           "USE_REPLYMAP"]:
            if config.getboolean("GENERAL", singleckey) not in [True, False]:
                raise ValueError("[\"GENERAL\"][\"" + singleckey + "\"] configuration invalid")

        if not config["GENERAL"]["ACTIVE_URIBLS"]:
            raise ValueError("no active URIBL configuration sections defined")

        for scuribl in config["GENERAL"]["ACTIVE_URIBLS"].split():
            if not config[scuribl]:
                raise ValueError("configuration section for active URIBL " + scuribl + " missing")
            elif not is_valid_domain(config[scuribl]["FQDN"]):
                raise ValueError("no valid FQDN given for active URIBL " + scuribl)

    except (KeyError, ValueError) as error:
        LOGIT.error("Configuration sanity tests failed: %s", error)
        print("BH")
        sys.exit(127)

    LOGIT.debug("Configuation sanity tests passed, good, processing...")

    # Apply configured logging level to avoid INFO/DEBUG clutter (thanks, cf5cec3a)...
    LOGIT.setLevel({"DEBUG": logging.DEBUG,
                    "INFO": logging.INFO,
                    "WARNING": logging.WARNING,
                    "ERROR": logging.ERROR}[config["GENERAL"]["LOGLEVEL"].upper()])

else:
    LOGIT.error("Supplied configuraion file path '%s' is not a file", CFILE)
    print("BH")
    sys.exit(127)

# Examine FQDNs of active URIBLs...
URIBL_DOMAINS = []
for active_uribl in config["GENERAL"]["ACTIVE_URIBLS"].split():
    URIBL_DOMAINS.append((active_uribl, config[active_uribl]["FQDN"].strip(".") + "."))

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.lifetime = config.getint("GENERAL", "RESOLVER_TIMEOUT")

# Test if specified URIBLs work correctly (according to RFC 5782 [section 5])...
PASSED_RFC_TEST = test_all_uribls(URIBL_DOMAINS)

# Depending on the configuration at the beginning of this script, further
# queries will or will not result in BH every time. Adjust log messages...
if not PASSED_RFC_TEST and config.getboolean("GENERAL", "RETURN_BH_ON_FAILED_RFC_TEST"):
    LOGIT.error("Aborting due to failed RFC 5782 (section 5) test for URIBL")
elif not PASSED_RFC_TEST:
    LOGIT.warning("There were failed RFC 5782 (section 5) URIBL tests. Possible fail open provocation, resuming normal operation, you have been warned...")
    PASSED_RFC_TEST = True
else:
    LOGIT.debug("All specified URIBLs are operational and passed RFC 5782 (section 5) test - excellent. Waiting for input...")

# Read domain names from STDIN in a while loop, and do URIBL lookups
# for every valid domin. In case it is not listed in URIBL, ERR is returned.
# BH is returned if input was invalid. Otherwise, return string is OK.
while True:
    try:
        QUERYDOMAIN = str(sys.stdin.readline().rstrip().split()[0])
    except (IndexError, KeyboardInterrupt):
        sys.exit(127)

    # Abort if domain was empty (no STDIN input received)
    if not QUERYDOMAIN:
        break

    # If the configuration requires a "fail close" behaviour (which is strongly recommended),
    # perform RFC 5782 (section 5) tests again every time a request is received. The rationale
    # for this is to avoid indefinitely broken DNSBL helpers, in case an URIBL was unavailable
    # for a short time at the beginning of operation. Otherwise, manual interaction is required
    # to return to an operational state - which is considered much worse in productive environments.
    if config.getboolean("GENERAL", "RETURN_BH_ON_FAILED_RFC_TEST") and not PASSED_RFC_TEST:
        if not test_all_uribls(URIBL_DOMAINS):
            print("BH")
            continue
        else:
            PASSED_RFC_TEST = True

    # Check if input is an IP address (we need to return ERR in such
    # cases, as most URIBLs are unable to handle them, and BH will result
    # in blocking direct IP communication)
    if is_ipaddress(QUERYDOMAIN):
        print("ERR")
        continue

    # Check if it is a valid domain, and return ERR instead of BH for the same reasons
    # as discussed in dnsbl-ip.py, "if not IPS" (DoS attack prevention).
    if not is_valid_domain(QUERYDOMAIN):
        LOGIT.info("queried destination '%s' is not a valid FQDN, returning 'ERR'", QUERYDOMAIN)
        print("ERR")
        continue

    query_result = False

    if config.getboolean("GENERAL", "USE_REPLYMAP"):
        replystring = "message=\""

    with concurrent.futures.ThreadPoolExecutor() as executor:
        tasks = []

        for active_uribl in URIBL_DOMAINS:
            tasks.append(executor.submit(query_uribl, config, active_uribl, QUERYDOMAIN))

        for singlequery in concurrent.futures.as_completed(tasks):
            (rstate, replymapstring) = singlequery.result()

            # This should not happen, returning BH in such cases and log a warning...
            if rstate is None:
                LOGIT.warning("got emtpy return state from concurrent task for destination '%s', returning 'BH' - please report this",
                              QUERYDOMAIN)
                print("BH")
                break

            elif rstate is True:
                query_result = True
                if config.getboolean("GENERAL", "USE_REPLYMAP"):
                    replystring = replystring + replymapstring

    if query_result and config.getboolean("GENERAL", "USE_REPLYMAP"):
        print("OK", replystring.strip(", ").strip() + "\"")
    elif query_result:
        print("OK")
    else:
        print("ERR")

# EOF
