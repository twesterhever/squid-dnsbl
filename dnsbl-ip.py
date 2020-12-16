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

    # Enumerate IPv6 addresses...
    ip6a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'AAAA'):
            ip6a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
        pass

    # Enumerate IPv4 addresses...
    ip4a = []
    try:
        for resolvedip in RESOLVER.query(domain, 'A'):
            ip4a.append(str(resolvedip))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
        pass

    # Assemble all IP addresses and return them back
    ips = ip6a + ip4a
    return ips


def resolve_nameserver_address(domain: str):
    """ Function call: resolve_nameserver_address(domain)

    This function takes a domain and enumerates all IPv4 and IPv6
    addresses of nameserver (NS) records for it. They are returned as
    an array. """

    # Check if this is a valid domain...
    if not is_valid_domain(domain):
        return None

    # Enumerate nameservers...
    ns = []
    try:
        for resolvedns in RESOLVER.query(domain, 'NS'):
            ns.append(str(resolvedns))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
        pass

    if not ns:
        return None

    ip6a = []
    ip4a = []

    for singlens in ns:
        # Enumerate IPv6 addresses...
        try:
            for resolvedip in RESOLVER.query(singlens, 'AAAA'):
                ip6a.append(str(resolvedip))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
            pass

        # Enumerate IPv4 addresses...
        try:
            for resolvedip in RESOLVER.query(singlens, 'A'):
                ip4a.append(str(resolvedip))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, ValueError):
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
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("RBL '%s' failed to answer RFC 5782 (section 5) test query for '127.0.0.1' within %s seconds",
                      rbltdomain, RESOLVER.lifetime)
        return False
    else:
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it lists 127.0.0.1", rbltdomain)
        return False

    # Test if 127.0.0.2 is listed
    try:
        RESOLVER.query((build_reverse_ip("127.0.0.2") + "." + rbltdomain), 'A')
    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
        LOGIT.error("RBL '%s' is violating RFC 5782 (section 5) as it does not list 127.0.0.2", rbltdomain)
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        LOGIT.warning("RBL '%s' failed to answer RFC 5782 (section 5) test query for '127.0.0.2' within %s seconds",
                      rbltdomain, RESOLVER.lifetime)
        return False
    else:
        LOGIT.debug("RBL '%s' is listing testpoint address 127.0.0.2 - good", rbltdomain)

    LOGIT.info("RBL '%s' seems to be operational and compliant to RFC 5782 (section 5) - good", rbltdomain)
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

    LOGIT.info("Configuation sanity tests passed, good, processing...")

    # Apply configured logging level to avoid INFO/DEBUG clutter (thanks, cf5cec3a)...
    LOGIT.setLevel({"DEBUG": logging.DEBUG,
                    "INFO": logging.INFO,
                    "WARNING": logging.WARNING,
                    "ERROR": logging.ERROR}[config["GENERAL"]["LOGLEVEL"].upper()])

else:
    LOGIT.error("Supplied configuraion file path '%s' is not a file", CFILE)
    print("BH")
    sys.exit(127)

# Examine FQDNs of active RBLs...
RBL_DOMAINS = []
for active_rbl in config["GENERAL"]["ACTIVE_RBLS"].split():
    RBL_DOMAINS.append((active_rbl, config[active_rbl]["FQDN"].strip(".") + "."))

# Set up resolver object
RESOLVER = dns.resolver.Resolver()

# Set timeout for resolving
RESOLVER.lifetime = config.getint("GENERAL", "RESOLVER_TIMEOUT")

# Test if specified RBLs work correctly (according to RFC 5782 [section 5])...
PASSED_RFC_TEST = True
for active_rbl in RBL_DOMAINS:
    if not test_rbl_rfc5782(active_rbl[1]):
        # In this case, an RBL has failed the test...
        LOGIT.warning("RFC 5782 (section 5) test for RBL '%s' failed", active_rbl[1])
        PASSED_RFC_TEST = False

# Depending on the configuration at the beginning of this script, further
# queries will or will not result in BH every time. Adjust log messages...
if not PASSED_RFC_TEST and config.getboolean("GENERAL", "RETURN_BH_ON_FAILED_RFC_TEST"):
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
    if config.getboolean("GENERAL", "RETURN_BH_ON_FAILED_RFC_TEST") and not PASSED_RFC_TEST:
        print("BH")
        continue

    # Enumerate whether query string is a domain or an IP address...
    try:
        IPS = [ipaddress.ip_address(QSTRING)]
    except (ValueError, AttributeError):
        # In this case, we are probably dealing with a domain
        IPS = resolve_addresses(QSTRING.strip(".") + ".")

        # In case nameserver checks are enabled and we are dealing with a domain, resolve their
        # nameserver IP addresses as well...
        if config.getboolean("GENERAL", "QUERY_NAMESERVER_IPS"):
            NSIPS = resolve_nameserver_address(QSTRING.strip(".") + ".")

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

        for active_rbl in RBL_DOMAINS:
            for idx, qip in enumerate(IPS):
                try:
                    answer = RESOLVER.query((build_reverse_ip(qip) + "." + active_rbl[1]), 'A')
                except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
                    qfailed = True
                except (dns.exception.Timeout, dns.resolver.NoNameservers):
                    LOGIT.warning("RBL '%s' failed to answer query for '%s' within %s seconds, returning 'BH'",
                                  active_rbl[1], build_reverse_ip(qip), RESOLVER.lifetime)
                    print("BH")
                    break
                else:
                    qfailed = False

                    # Concatenate responses and log them...
                    responses = ""
                    rblmapoutput = "blacklist='"
                    for rdata in answer:
                        rdata = str(rdata)
                        responses = responses + rdata + " "

                        # If a RBL map file is present, the corresponding key to each DNS reply
                        # for this RBL is enumerated and passed to Squid via additional keywords...
                        if config.getboolean("GENERAL", "USE_REPLYMAP"):
                            try:
                                rblmapoutput += config[active_rbl[0]][rdata] + ", "
                            except KeyError:
                                pass

                    LOGIT.warning("RBL hit on '%s.%s' with response '%s' (queried destination: '%s')",
                                  build_reverse_ip(qip), active_rbl[1], responses.strip(), QSTRING)

                    if config.getboolean("GENERAL", "USE_REPLYMAP"):
                        rblmapoutput = rblmapoutput.strip(", ")
                        rblmapoutput += "'"
                        print("OK", rblmapoutput)
                    else:
                        print("OK")
                    break
            else:
                continue
            break

        if qfailed and config.getboolean("GENERAL", "QUERY_NAMESERVER_IPS"):
            for active_rbl in RBL_DOMAINS:
                for idx, qip in enumerate(NSIPS):
                    try:
                        answer = RESOLVER.query((build_reverse_ip(qip) + "." + active_rbl[1]), 'A')
                    except (dns.resolver.NXDOMAIN, dns.name.LabelTooLong, dns.name.EmptyLabel):
                        qfailed = True
                    except (dns.exception.Timeout, dns.resolver.NoNameservers):
                        LOGIT.warning("RBL '%s' failed to answer query for nameserver IP '%s' (queried destination: '%s') within %s seconds, returning 'BH'",
                                      active_rbl[1], build_reverse_ip(qip), QSTRING, RESOLVER.lifetime)
                        print("BH")
                        break
                    else:
                        qfailed = False

                        # Concatenate responses and log them...
                        responses = ""
                        rblmapoutput = "blacklist='"
                        for rdata in answer:
                            rdata = str(rdata)
                            responses = responses + rdata + " "

                            # If a RBL map file is present, the corresponding key to each DNS reply
                            # for this RBL is enumerated and passed to Squid via additional keywords...
                            if config.getboolean("GENERAL", "USE_REPLYMAP"):
                                try:
                                    rblmapoutput += config[active_rbl[0]][rdata] + ", "
                                except KeyError:
                                    pass

                        LOGIT.warning("RBL hit on nameserver IP %s ('%s.%s') with response '%s' (queried destination: '%s')",
                                      qip, build_reverse_ip(qip), active_rbl[1], responses.strip(), QSTRING)

                        if config.getboolean("GENERAL", "USE_REPLYMAP"):
                            rblmapoutput = rblmapoutput.strip(", ")
                            rblmapoutput += "'"
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
