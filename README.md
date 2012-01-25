LDNSX: Easy DNS (including DNSSEC) via ldns
===========================================

TL;DR: Working with DNS should't be terrifying.

ldns is a great library. It is a powerfull tool for
working with DNS. python-ldns it is a straight up clone of the C
interface, howver that is not a very good interface for python. Its
documentation is incomplete and some functions don't work as
described. And some objects don't have a full python API.

ldnsx aims to fix this. It wraps around the ldns python bindings,
working around its limitations and providing a well-documented, more
pythonistic interface.

Written by Christopher Olah (chris@colah.ca), partly in the employment of Xelerance.

Examples
========

Query the default resolver for google.com's A records. Print the response
packet.

```python
import ldnsx
resolver = ldnsx.resolver()
print resolver.query("google.com","A")
```

Print the NS records for com. from f.root-servers.net if we get a
response, else an error message.

```python
import ldnsx
pkt = ldnsx.resolver("f.root-servers.net").query("com.","NS")
if pkt:
    for rr in pkt.answer():
        print rr
else:
    print "response not received" 
```

Working With Resolvers
-----------------------

Making resolvers is easy!

```python
>>> from ldnsx import resolver
>>> resolver() # from /etc/resolv.conf
<resolver: 192.168.111.9>
>>> resolver("") # resolver with no nameservers
<resolver: >
>>> resolver("193.110.157.135") #resolver pointing to ip addr
<resolver: 193.110.157.135>
>>> resolver("f.root-servers.net") # resolver pointing ip address(es) resolved from name
<resolver: 2001:500:2f::f, 192.5.5.241>
>>> resolver("193.110.157.135, 193.110.157.136") 
>>> # resolver pointing to multiple ip addr, first takes precedence.
<resolver: 193.110.157.136, 193.110.157.135>
```

So is playing around with their nameservers!

```python
>>> import ldnsx
>>> res = ldnsx.resolver("192.168.1.1")
>>> res.add_nameserver("192.168.1.2")
>>> res.add_nameserver("192.168.1.3")
>>> res.nameservers_ip()
["192.168.1.1","192.168.1.2","192.168.1.3"]
```

And querying!

```python
>>> from ldnsx import resolver
>>> res= resolver()
>>> res.query("cow.com","A")
;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 7663
;; flags: qr rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0 
;; QUESTION SECTION:
;; cow.com.     IN      A
;; ANSWER SECTION:
cow.com.        300     IN      A       208.87.34.18
;; AUTHORITY SECTION:
;; ADDITIONAL SECTION:
;; Query time: 313 msec
;; SERVER: 192.168.111.9
;; WHEN: Fri Jun  3 11:01:02 2011
;; MSG SIZE  rcvd: 41
```

Fun With Querying
-----------------

We can do all sorts of stuff with querying!

Let's get some A records!

```python
google_a_records = resolver.query("google.com","A").answer()
```

Using DNSSEC is easy :)

```python
dnssec_pkt = ldnsx.resolver(dnssec=True).query("xelerance.com")
```

We let you use strings to make things easy, but if you prefer stay close to DNS...

```python
AAAA = 28
resolver.query("ipv6.google.com", AAAA)
```

AXFR
----

Let's get a list of the tlds -- gotta catch em all!

We'll need to [AXFR](http://en.wikipedia.org/wiki/DNS_zone_transfer), of course.

```python
tlds = []
for rr in resolver("f.root-servers.net").AXFR("."):
    if rr.rr_type() == "NS":
       tlds.append(rr.owner())
```

Working With the Results
------------------------

It is, of course, easy to access packet sections.

```python
>>> res = ldnsx.resolver()
>>> pkt = res.query("google.ca","A")
>>> pkt.answer()
[google.ca.     28      IN      A       74.125.91.99
, google.ca.    28      IN      A       74.125.91.105
, google.ca.    28      IN      A       74.125.91.147
, google.ca.    28      IN      A       74.125.91.103
, google.ca.    28      IN      A       74.125.91.104
, google.ca.    28      IN      A       74.125.91.106
]
```

We provide filtering to make your life easy!

```python
>>> pkt = ldnsx.query("cow.com","ANY")
>>> pkt.answer()
[cow.com.       276     IN      A       208.87.32.75
, cow.com.      3576    IN      NS      sell.internettraffic.com.
, cow.com.      3576    IN      NS      buy.internettraffic.com.
, cow.com.      3576    IN      SOA     buy.internettraffic.com. hostmaster.hostingnet.com. 1308785320 10800 3600 604800 3600
]
>>> pkt.answer(rr_type="A")
[cow.com.       276     IN      A       208.87.32.75
]
>>> pkt.answer(rr_type="A|NS")
[cow.com.       276     IN      A       208.87.32.75
, cow.com.      3576    IN      NS      sell.internettraffic.com.
, cow.com.      3576    IN      NS      buy.internettraffic.com.
]
>>> pkt.answer(rr_type="!NS")
[cow.com.       276     IN      A       208.87.32.75
, cow.com.      3576    IN      SOA     buy.internettraffic.com. hostmaster.hostingnet.com. 1308785320 10800 3600 604800 3600
]
```

