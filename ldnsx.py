#!/usr/bin/python
# (c) Christopher Olah <colah@xelerance.com>, 2011. Xelerance.

""" Easy DNS (including DNSSEC) via ldns.

In many respects, ldns is a great library. It is a powerfull tool for working with DNS. Unfortunatly, while it has python bindings, they are deeply lacking -- a thin, incomplete wrapper around the C library. The documentation is incomplete, functions don't work as described, some objects don't a full python API. Furthermore, it is a straight up clone of the C interface, which often isn't a very good interface for python. All this leads to a difficult to use library.

ldnsx aims to fix this. It wraps around the ldns python bindings, working around its limitations and providing a more pythonistic interface.

EXAMPLES:

Ask the default nameserver for the A resource records for google.com

> import ldnsx
> resolver = ldnsx.resolver()
> for rr in resolver.query("google.com","A"):
>     print rr

Ask f.root-servers.net for the DS records for .com:

> import ldnsx
> resolver = ldnsx.resolver("f.root-servers.net")
> for rr in resolver.query("com.","DS"):
>     print rr

UNIT TESTS:

Writing unit tests for a DNS library is somewhat tricky since results generally depend on web servers, but here are a few:

>>> res   =   resolver("192.168.1.1")
>>> res.add_nameserver("192.168.1.2")
>>> res.add_nameserver("192.168.1.3")
>>> res.nameservers()
["192.168.1.1","192.168.1.2","192.168.1.3"]

"""


import ldns
import re
import time

_dns_types={
	"A"    : ldns.LDNS_RR_TYPE_A,
	"A6"   : ldns.LDNS_RR_TYPE_A6,
	"AAAA" : ldns.LDNS_RR_TYPE_AAAA,
	"AFSDB": ldns.LDNS_RR_TYPE_AFSDB,
	"ANY"  : ldns.LDNS_RR_TYPE_ANY,
	"APL"  : ldns.LDNS_RR_TYPE_APL,
	"ATMA" : ldns.LDNS_RR_TYPE_ATMA,
	"AXFR" : ldns.LDNS_RR_TYPE_AXFR,
	"CERT" : ldns.LDNS_RR_TYPE_CERT,
	"CNAME": ldns.LDNS_RR_TYPE_CNAME,
	"COUNT": ldns.LDNS_RR_TYPE_COUNT,
	"DHCID": ldns.LDNS_RR_TYPE_DHCID,
	"DLV"  : ldns.LDNS_RR_TYPE_DLV,
	"DNAME": ldns.LDNS_RR_TYPE_DNAME,
	"DNSKEY": ldns.LDNS_RR_TYPE_DNSKEY,
	"DS"   : ldns.LDNS_RR_TYPE_DS,
	"EID"  : ldns.LDNS_RR_TYPE_EID,
	"FIRST": ldns.LDNS_RR_TYPE_FIRST,
	"GID"  : ldns.LDNS_RR_TYPE_GID,
	"GPOS" : ldns.LDNS_RR_TYPE_GPOS,
	"HINFO": ldns.LDNS_RR_TYPE_HINFO,
	"IPSECKEY": ldns.LDNS_RR_TYPE_IPSECKEY,
	"ISDN" : ldns.LDNS_RR_TYPE_ISDN,
	"IXFR" : ldns.LDNS_RR_TYPE_IXFR,
	"KEY"  : ldns.LDNS_RR_TYPE_KEY,
	"KX"   : ldns.LDNS_RR_TYPE_KX,
	"LAST" : ldns.LDNS_RR_TYPE_LAST,
	"LOC"  : ldns.LDNS_RR_TYPE_LOC,
	"MAILA": ldns.LDNS_RR_TYPE_MAILA,
	"MAILB": ldns.LDNS_RR_TYPE_MAILB,
	"MB"   : ldns.LDNS_RR_TYPE_MB,
	"MD"   : ldns.LDNS_RR_TYPE_MD,
	"MF"   : ldns.LDNS_RR_TYPE_MF,
	"MG"   : ldns.LDNS_RR_TYPE_MG,
	"MINFO": ldns.LDNS_RR_TYPE_MINFO,
	"MR"   : ldns.LDNS_RR_TYPE_MR,
	"MX"   : ldns.LDNS_RR_TYPE_MX,
	"NAPTR": ldns.LDNS_RR_TYPE_NAPTR,
	"NIMLOC": ldns.LDNS_RR_TYPE_NIMLOC,
	"NS"   : ldns.LDNS_RR_TYPE_NS,
	"NSAP" : ldns.LDNS_RR_TYPE_NSAP,
	"NSAP_PTR" : ldns.LDNS_RR_TYPE_NSAP_PTR,
	"NSEC" : ldns.LDNS_RR_TYPE_NSEC,
	"NSEC3": ldns.LDNS_RR_TYPE_NSEC3,
	"NSEC3PARAMS" : ldns.LDNS_RR_TYPE_NSEC3PARAMS,
	"NULL" : ldns.LDNS_RR_TYPE_NULL,
	"NXT"  : ldns.LDNS_RR_TYPE_NXT,
	"OPT"  : ldns.LDNS_RR_TYPE_OPT,
	"PTR"  : ldns.LDNS_RR_TYPE_PTR,
	"PX"   : ldns.LDNS_RR_TYPE_PX,
	"RP"   : ldns.LDNS_RR_TYPE_RP,
	"RRSIG": ldns.LDNS_RR_TYPE_RRSIG,
	"RT"   : ldns.LDNS_RR_TYPE_RT,
	"SIG"  : ldns.LDNS_RR_TYPE_SIG,
	"SINK" : ldns.LDNS_RR_TYPE_SINK,
	"SOA"  : ldns.LDNS_RR_TYPE_SOA,
	"SRV"  : ldns.LDNS_RR_TYPE_SRV,
	"SSHFP": ldns.LDNS_RR_TYPE_SSHFP,
	"TSIG" : ldns.LDNS_RR_TYPE_TSIG,
	"TXT"  : ldns.LDNS_RR_TYPE_TXT,
	"UID"  : ldns.LDNS_RR_TYPE_UID,
	"UINFO": ldns.LDNS_RR_TYPE_UINFO,
	"UNSPEC": ldns.LDNS_RR_TYPE_UNSPEC,
	"WKS"  : ldns.LDNS_RR_TYPE_WKS,
	"X25"  : ldns.LDNS_RR_TYPE_X25
}

class resolver:
	""" A wrapper around ldns.ldns_resolver. """
	
	def __init__(self, ns = ""):
		"""resolver constructor
			
			  * ns -- the nameserver, defaults to settings from /etc/resolv.conf

			EXAMPLES:

			> resolver("193.110.157.135")
			> resolver("f.root-servers.net")

			"""
		if ns == "":
			self._ldns_resolver = ldns.ldns_resolver.new_frm_file("/etc/resolv.conf")
		elif re.match("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",ns):
			self._ldns_resolver = ldns.ldns_resolver.new_frm_file("/etc/resolv.conf")
			self.drop_nameservers()
			self.add_nameserver(ns)
		else:
			# The following only works on some machines, so we don't use it.
			# (Despite having the same version of ldns and freinds)
			#> default_resolver = resolver()
			#> self._ldns_resolver = ldns.ldns_resolver_new()
			#> address = default_resolver._ldns_resolver.get_addr_by_name(ns)
			#> self._ldns_resolver.push_nameserver_rr_list(address)
			# Instead we do the following, as in sshfp dane
			resolver = ldns.ldns_resolver.new_frm_file("/etc/resolv.conf")
			address = resolver.get_addr_by_name(ns)
			while resolver.pop_nameserver():
				pass
			for rr in address.rrs():
				resolver.push_nameserver_rr(rr)
			self._ldns_resolver=resolver
			# This approach didn't work by constructing with ldns_resolver_new()
			# and then pushing rrs on some computers. It seems one _must_ use 
			# new_frm_file, pop, and then push.
	
	def query(self, name, dns_type, dns_class="IN", tries = 1):
		"""Run a query on the resolver.
			
			  * name -- name to query for
			  * dns_type -- the record type to query for (see suported_DNS_types)
			  * dns_class -- the class to query for, defaults to IN (Internet)
			  * tries -- the number of times to attempt to acheive query in case of packet loss, etc

			EXAMPLE:

			> for rr in resolver.query("google.com","A")
			>     print rr


		"""
		if not dns_type in _dns_types.keys():
			raise Exception("Unknown DNS Record Type")
		if tries == 0: return None
		pkt = self._ldns_resolver.query(name, _dns_types[dns_type], ldns.LDNS_RR_CLASS_IN)
		if not pkt:
			time.sleep(1)
			return self.query(name, dns_type, dns_class=dns_class, tries = tries-1) 
		ret = []
		for rr in pkt.answer().rrs():
			ret.append([str(rr.owner()),rr.ttl(),rr.get_class_str(),rr.get_type_str()]+[str(rdf) for rdf in rr.rdfs()])
		return ret
	
	def suported_DNS_types(self):
		""" Returns the supported DNS record types.

			For information on what they are, refer to 
			https://secure.wikimedia.org/wikipedia/en/wiki/List_of_DNS_record_types

		"""
		return _dns_types.keys()
	
	def AXFR(self,name):
		"""AXFR for name
			
			This function is a generator. As it AXFRs it will yield you the records.

		"""
		if self._ldns_resolver.axfr_start(ldns.ldns_dname(name), ldns.LDNS_RR_CLASS_IN) != ldns.LDNS_STATUS_OK:
			raise Exception("Starting AXFR failed. Error: %s" % ldns.ldns_get_errorstr_by_id(status))
		pres = self._ldns_resolver.axfr_next()
		while pres:
			yield (str(pres.owner()),pres.ttl(),pres.get_class_str(),pres.get_type_str())
			pres = self._ldns_resolver.axfr_next()

	def nameservers(self):
		""" returns a list of the resolvers nameservers (as IP addr)
		
		"""
		nm_stack2 =[]
		nm_str_stack2=[]
		nm = self._ldns_resolver.pop_nameserver()
		while nm:
			nm_stack2.append(nm)
			nm_str_stack2.append(str(nm))
			nm = self._ldns_resolver.pop_nameserver()
		for nm in nm_stack2:
			self._ldns_resolver.push_nameserver(nm)
		nm_str_stack2.reverse()
		return nm_str_stack2


	def add_nameserver(self,ns):
		""" NOT FULLY IMPLEMENTED YET"""
		pass
		if re.match("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",ns):
			address = ldns.ldns_rdf_new_frm_str(5,ns)
			self._ldns_resolver.push_nameserver(address)
		else:
			raise Exception("push nameserver has not yet implemented pushing names")

	def drop_nameservers(self):
		"""Drops all nameservers.
			This function causes the resolver to forget all nameservers.
		"""
		while self._ldns_resolver.pop_nameserver():
			pass

	def __repr__(self):
		return "<resolver: %s>" % repr(self.nameservers())[1:-1]


