# Direct IP Scanner

Discover IPs of popular domains based on IP ranges


## Finding IPs for a domain

You first need to find their autonomous system number. It's in the whois record for any of their IP addresses.

These examples use GNU jwhois.

```
$ host www.facebook.com
www.facebook.com is an alias for star.c10r.facebook.com.
star.c10r.facebook.com has address 173.252.120.6
star.c10r.facebook.com has IPv6 address 2a03:2880:2130:cf05:face:b00c:0:1
star.c10r.facebook.com mail is handled by 10 msgin.t.facebook.com.
```

```
$ whois -h whois.radb.net 173.252.120.6 | grep origin
origin:     AS32934
origin:     AS38621
```

Make sure it actually belongs to Facebook. If the domain is of a small website it won't have it's onw AS.

```
$ whois -h whois.radb.net AS32934
$ whois -h whois.radb.net AS38621
```

Now we know which is Facebook's ASN; let's get their IPv4 address ranges.

$ whois -h whois.radb.net -- -i origin -T route AS32934 | grep route: 

And finally their IPv6 address ranges.

$ whois -h whois.radb.net -- -i origin -T route6 AS32934 | grep route6:

Repeat for all their ASNs, if they actually have more than one.
