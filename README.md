# Squid helpers for querying domains and IPs against DNSBLs

The [Squid](http://www.squid-cache.org/) proxy software is widely
used, and so is its ability to introduce access limits, i.e.
by only allowing traffic to well-known ports.

While Squid is able to handle file based blocklists by taking
advantage of [SquidGuard](http://squidguard.org/), the usage
of DNSBLs has never been that easy. There is
[some patch available](http://squidguard.org/Downloads/Contrib/squidGuard-1.4-dnsbl.patch)
which adds this feature, but it did not seem to made it into
many distribution packages.

Worse, SquidGuard does not support querying resolved IP
addresses of a domain against RBLs. Since cyber criminals
tend to host multiple domains on the same IP address, this
might be useful.

This repository aims to close this gap by providing to Python 3.x
based scripts which can be accessed by Squid as external helpers.
In order to work under chrooted Squid instances on BSD,
`/usr/bin/env -S python3 -u` needs to be changed into `/usr/local/bin/python3 -u`.

## dnsbl.py
This script looks up domains against one or more
[URIBL](https://en.wikipedia.org/wiki/DNSBL#URI_DNSBL) given as
command line arguments:
```
./dnsbl.py dbl.spamhaus.org multi.uribl.com
```
It returns `OK` if a domain was found, and `ERR` in case it was not.

Depending on use this script in combination with a black- or
whitelist, one might to block connection attempts to domains
caused `OK` (blacklist) or `ERR` (whitelist).

This basically implements the function of mentioned SquidGuard
patch above.

## dnsbl-ip.py
This script looks up any resolved IP address against one or
more [RBL](https://en.wikipedia.org/wiki/DNSBL#DNSBL_queries)
given as command line arguments:
```
./dnsbl-ip.py sbl-xbl.spamhaus.org bl.blocklist.de
```
Similar to its counterpart above, it returns `OK` if _any_
IP address was found, and `ERR` if _none_ of them were.

This script handles both IPv4 and IPv6 addresses.

Be careful in your RBL choice: For example, if the
[Spamhaus ZEN](https://www.spamhaus.org/zen/) RBL is used,
connection attempts to dynamic IP ranges will be blocked, too.

## Advanced Settings
There are some settings for advanced usage of these DNSBL helpers. In
order to avoid configuration file complexity (reading, parsing, etc.),
these settings can be changed at the beginning of `dnsbl.py` and `dnsbl-ip.py`.

### Passing human-readable blacklist string to error pages
Squid is capable of receiving additional messages from helpers which
can be displayed on error pages by using the `%o` statement. Refer to
http://www.squid-cache.org/Doc/config/external_acl_type/ for further information.

In some scenarios, telling the user which blacklists caused a connection
attempt to be rejected might be desired. To do so, a JSON map can be
specified by modifiying `RBL_MAP` directly or saved to a file which location
is passed by `RBL_MAP_FILE`.

Expected JSON map syntax is as follows:
```
{"127.0.0.2": "blacklist A",
 "127.0.0.3": "blacklist B",
 "127.0.0.250": "our own custom blacklist",
 ...}
```

Please note: This helper stops after first blacklist match. If desired,
consider building an aggregated RBL with distinct DNS answers returned
all at once (e.g. by running a custom `rbldnsd` instance).

### Handling of failed RFC 5782 (section 5) tests
Both DNSBL helpers perform santiy tests as documented in RFC 5782 (section 5)
to make sure given RBLs and URIBLs are reachable and working correctly. If _any_
of these tests fail, a helper will simply return `BH` for any domain or IP
address.

Setting `RETURN_BH_ON_FAILED_RFC_TEST` to `False` enforces normal operation
of the helpers, but is _strongly discouraged_ as is allows them to fail-open
silenty.

## Example Squid configuration
In order to use the scripts in a Squid config, you will
need to set up a separate ACL for both of them, defining
them as an external ACL helper.

Here is the corresponding snippet of a `squid.conf` file:

```
external_acl_type dnsbliphelper children-max=10 children-startup=2 %DST /usr/local/bin/dnsbl-ip.py sbl-xbl.spamhaus.org bl.blocklist.de
acl dnsblip external dnsbliphelper

external_acl_type dnsbldomhelper children-max=10 children-startup=2 %DST /usr/local/bin/dnsbl.py dbl.spamhaus.org multi.uribl.com
acl dnsbldom external dnsbldomhelper
```

The scripts can be used for both blacklisting and whitelisting.
In case of blacklisting, just deny acces to the defined ACL:
```
http_access deny dnsblip
http_access deny dnsbldom
```

For usage as a whitelist, choose `allow` instead of `deny` here.
You might want to rename the ACL then, as the given example
would be misleading.

## Further Readings
* [Statistics concerning hit and FP rate of blacklists](https://www.intra2net.com/en/support/antispam/index.php_sort=type_order=desc.html)
* [Comparison of DNS blacklists](https://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists)
* [Corresponding Squid documentation](http://www.squid-cache.org/Doc/config/external_acl_type/)
