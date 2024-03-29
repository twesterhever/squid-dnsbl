#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

""" dnsbl-ip [.py]

Squid helper for checking any domain or IP against a specified RBL.
Domains are read from STDIN and checked if they are valid. If
so, a DNS query is performed for any resolved IP address and its
result enumerated. IP adresses are checked agains RBL directly.

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

    # List of enumerated IPs, default empty...
    ips = []

    # Resolve A and AAAA records of that domain in parallel...
    with concurrent.futures.ThreadPoolExecutor() as executor:
        tasks = []

        for qtype in ["A", "AAAA"]:
            tasks.append(executor.submit(RESOLVER.resolve, domain, qtype))

        for singlequery in concurrent.futures.as_completed(tasks):
            # ... and write the results into the IP address list
            try:
                for singleip in singlequery.result():
                    ips.append(str(singleip))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
                # Catch possible DNS exceptions...
                pass

    # Deduplicate...
    ips = set(ips)

    return ips


def resolve_nameservers(domain: str):
    """ Function call: resolve_nameservers(domain)

    This function takes a domain and enumerates all FQDNs of nameserver (NS)
    recrods for it. They are returned as an array, and can then be used for
    assessing the reputation of the queried destination based on its nameserver
    infrastructure.

    Note that NS DNS queries are subject to forgery attempts: A rogue domain
    may lie about its NS when queried directly, or even return no nameservers
    at all. Only the delegation data in the superior zone (such as the TLD)
    cannot be forged without crippling a domains' functionality.
    """

    # Check if this is a valid domain...
    if not is_valid_domain(domain):
        return None

    # Enumerate nameservers...
    ns = []
    try:
        for resolvedns in RESOLVER.resolve(domain, "NS"):
            ns.append(str(resolvedns))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
        pass

    if not ns:
        # In case there were none, trim the queried destination to its eSLD and try again...
        esld = ".".join(extractobject(domain)[1:3])
        if not esld == domain:
            ns = resolve_nameservers(esld)

    # Deduplicate...
    ns = set(ns)

    return ns


def query_rbl(config: dict, rbldomain: tuple, queriedip: str, qstring: str, nsmode: bool = False):
    """ Function call: query_rbl(ConfigParser object,
                                 RBL domain tuple,
                                 IP address to query,
                                 queried destination for logging purposes,
                                 is queried IP a nameserver IP [logging purposes]?)

    This function looks up the given IP addresses against the RBL. It returns a tuple
    of a Boolean indiciating whether or not the IP address was listed (or None in case
    the query failed), and a string containing reply map information (if configured),
    being empty otherwise.
    """

    returnstate = None
    rblmapoutput = ""

    try:
        answer = RESOLVER.resolve((build_reverse_ip(queriedip) + "." + rbldomain[1]), "A")
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        returnstate = False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        if nsmode:
            LOGIT.warning("RBL '%s' failed to answer query for nameserver IP '%s' ('%s.%s', queried destination: '%s') within %s seconds, returning 'BH'",
                          rbldomain[1], queriedip, build_reverse_ip(queriedip), rbldomain[1], qstring, RESOLVER.lifetime)
        else:
            LOGIT.warning("RBL '%s' failed to answer query for '%s' ('%s.%s', queried destination: '%s') within %s seconds, returning 'None' (i. e. 'BH') to calling function...",
                          rbldomain[1], queriedip, build_reverse_ip(queriedip), rbldomain[1], qstring, RESOLVER.lifetime)
    else:
        returnstate = True

        # Concatenate responses and log them...
        responses = ""

        for rdata in answer:
            rdata = str(rdata)
            responses = responses + rdata + " "

            # If a RBL reply map is configured, the corresponding key to each DNS reply
            # for this RBL is enumerated and returned as a combined string...
            if config.getboolean("GENERAL", "USE_REPLYMAP"):
                try:
                    rblmapoutput += config[active_rbl[0]][rdata] + " (" + str(queriedip) + "), "
                except KeyError:
                    LOGIT.info("replymap is active, but configuration file does not contain data for %s (%s)",
                               active_rbl[0], rdata)
                    rblmapoutput = "N/A "

        if nsmode:
            LOGIT.warning("RBL hit on nameserver IP %s ('%s.%s') with response '%s' (queried destination: '%s')",
                          queriedip, build_reverse_ip(queriedip), rbldomain[1], responses.strip(), qstring)
        else:
            LOGIT.warning("RBL hit on %s ('%s.%s') with response '%s' (queried destination: '%s')",
                          queriedip, build_reverse_ip(queriedip), rbldomain[1], responses.strip(), qstring)

    return (returnstate, rblmapoutput)


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
        RESOLVER.resolve((build_reverse_ip("127.0.0.1") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.debug("RBL '%s' is not listing testpoint address 127.0.0.1 - good", rbltdomain)
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("RBL '%s' failed to answer RFC 5782 (section 5) test query for '127.0.0.1' within %s seconds",
                      rbltdomain, RESOLVER.lifetime)
        return False
    else:
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it lists 127.0.0.1", rbltdomain)
        return False

    # Test if 127.0.0.2 is listed
    try:
        RESOLVER.resolve((build_reverse_ip("127.0.0.2") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it does not list 127.0.0.2", rbltdomain)
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("RBL '%s' failed to answer RFC 5782 (section 5) test query for '127.0.0.2' within %s seconds",
                      rbltdomain, RESOLVER.lifetime)
        return False
    else:
        LOGIT.debug("RBL '%s' is listing testpoint address 127.0.0.2 - good", rbltdomain)

    LOGIT.debug("RBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", rbltdomain)
    return True


def test_all_rbls(rbl_domains: list):
    """ Function call: test_all_rbls(list of RBLSs enabled)

    Abstraction layer function for performing RFC 5782 (section 5) tests for all
    RBLs configured and enabled. Returns True if all of them pass these tests, and
    False otherwise.
    """

    for single_rbl in rbl_domains:
        if not test_rbl_rfc5782(single_rbl[1]):
            # in this case, an RBL has failed the test...
            LOGIT.warning("RFC 5782 (section 5) test for RBL '%s' failed", single_rbl[1])
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
                           "QUERY_NAMESERVER_IPS",
                           "USE_REPLYMAP"]:
            if config.getboolean("GENERAL", singleckey) not in [True, False]:
                raise ValueError("[\"GENERAL\"][\"" + singleckey + "\"] configuration invalid")

        if not config["GENERAL"]["ACTIVE_RBLS"]:
            raise ValueError("no active RBL configuration sections defined")

        for scrbl in config["GENERAL"]["ACTIVE_RBLS"].split():
            if not config[scrbl]:
                raise ValueError("configuration section for active RBL " + scrbl + " missing")
            elif not is_valid_domain(config[scrbl]["FQDN"]):
                raise ValueError("no valid FQDN given for active RBL " + scrbl)

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

# Load tldextract module, if necessary. Note that live HTTP fetching of the latest
# public suffix list snapshot is disabled here, since we cannot assume direct
# internet connnectivity. Thus, disable tldextract caching completely, since there is
# nothing to be cached.
if config.getboolean("GENERAL", "QUERY_NAMESERVER_IPS"):
    import tldextract
    extractobject = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)

# Examine FQDNs of active RBLs...
RBL_DOMAINS = []
for active_rbl in config["GENERAL"]["ACTIVE_RBLS"].split():
    RBL_DOMAINS.append((active_rbl, config[active_rbl]["FQDN"].strip(".") + "."))

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.lifetime = config.getint("GENERAL", "RESOLVER_TIMEOUT")

# Test if specified RBLs work correctly (according to RFC 5782 [section 5])...
PASSED_RFC_TEST = test_all_rbls(RBL_DOMAINS)

# Depending on the configuration at the beginning of this script, further
# queries will or will not result in BH every time. Adjust log messages...
if not PASSED_RFC_TEST and config.getboolean("GENERAL", "RETURN_BH_ON_FAILED_RFC_TEST"):
    LOGIT.error("Aborting due to failed RFC 5782 (section 5) test for RBL")
elif not PASSED_RFC_TEST:
    LOGIT.warning("There were failed RFC 5782 (section 5) RBL tests. Possible fail open provocation, resuming normal operation, you have been warned...")
    PASSED_RFC_TEST = True
else:
    LOGIT.debug("All specified RBLs are operational and passed RFC 5782 (section 5) test - excellent. Waiting for input...")

# Read domain names or IP addresses from STDIN in a while loop, and do RBL lookups
# for every valid domin or IP address. In case it is not listed in RBL, ERR is returned.
# BH is returned if input was invalid. Otherwise, return string is OK.
while True:
    try:
        QSTRING = str(sys.stdin.readline().rstrip().split()[0])
    except (IndexError, KeyboardInterrupt):
        sys.exit(127)

    # Abort if query string was empty (no STDIN input received)
    if not QSTRING:
        break

    # If the configuration requires a "fail close" behaviour (which is strongly recommended),
    # perform RFC 5782 (section 5) tests again every time a request is received. The rationale
    # for this is to avoid indefinitely broken DNSBL helpers, in case a RBL was unavailable
    # for a short time at the beginning of operation. Otherwise, manual interaction is required
    # to return to an operational state - which is considered much worse in productive environments.
    if config.getboolean("GENERAL", "RETURN_BH_ON_FAILED_RFC_TEST") and not PASSED_RFC_TEST:
        if not test_all_rbls(RBL_DOMAINS):
            print("BH")
            continue
        else:
            PASSED_RFC_TEST = True

    # Enumerate whether query string is a domain or an IP address...
    try:
        IPS = [ipaddress.ip_address(QSTRING)]
    except (ValueError, AttributeError):
        # In this case, we are most probably dealing with a domain...
        with concurrent.futures.ThreadPoolExecutor() as executor:
            IPS = executor.submit(resolve_addresses, QSTRING.strip(".") + ".").result()

            # In case nameserver checks are enabled and we are dealing with a domain, resolve
            # the nameserver FQDNs and IPs addresses as well...
            if config.getboolean("GENERAL", "QUERY_NAMESERVER_IPS"):
                NSFQDNS = executor.submit(resolve_nameservers,
                                          QSTRING.strip(".") + ".").result()

                if NSFQDNS:
                    NSIPS = []
                    for singlens in NSFQDNS:
                        NSIPS.extend(list(executor.submit(resolve_addresses, singlens).result()))

                if NSIPS:
                    # Deduplicate...
                    NSIPS = set(NSIPS)
    else:
        NSFQDNS = []
        NSIPS = []

    # Check if we have some IP addresses or nameserver data to lookup for...
    if not IPS and not NSFQDNS and not NSIPS:
        # ... if not, we'll return ERR instead of BH, since the latter one causes Squid
        # to display "permission denied" messages to the client, which is confusing.
        #
        # ERR is considered to be safe here, as Squid won't be able to establish a
        # connection anyway, no matter whether the destination is blacklisted or not,
        # provided both Squid and this script use the same DNS resolver.
        LOGIT.info("Unable to retrieve any A/AAAA/NS record for queried destination '%s', returning ERR...", QSTRING)
        print("ERR")
    else:
        query_result = False

        if config.getboolean("GENERAL", "USE_REPLYMAP"):
            replystring = "message=\""

        with concurrent.futures.ThreadPoolExecutor() as executor:
            tasks = []

            for active_rbl in RBL_DOMAINS:
                for idx, qip in enumerate(IPS):
                    tasks.append(executor.submit(query_rbl,
                                                 config,
                                                 active_rbl,
                                                 qip,
                                                 QSTRING,
                                                 False))

            if config.getboolean("GENERAL", "QUERY_NAMESERVER_IPS"):
                if not NSIPS:
                    LOGIT.debug("Skipping nameserver checks for '%s' since no nameserver IPs could be enumerated",
                                QSTRING)
                else:
                    for active_rbl in RBL_DOMAINS:
                        for idx, qip in enumerate(NSIPS):
                            tasks.append(executor.submit(query_rbl,
                                                         config,
                                                         active_rbl,
                                                         qip,
                                                         QSTRING,
                                                         True))

            for singlequery in concurrent.futures.as_completed(tasks):
                (rstate, replymapstring) = singlequery.result()

                # This should not happen, returning BH in such cases and log a warning...
                if rstate is None:
                    LOGIT.warning("got emtpy return state from concurrent task for destination '%s', returning 'BH' - please report this",
                                  QSTRING)
                    print("BH")
                    executor.shutdown(wait=False)
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
