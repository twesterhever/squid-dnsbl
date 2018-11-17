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
In order to be compatible to chrooted Squid instances on BSD,
`/usr/local/bin/python3` is hardcoded, but can be easily changed
to `/usr/bin/env python3` on Linux systems.

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
