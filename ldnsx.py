#!/usr/bin/python
# (c) Christopher Olah <colah@xelerance.com>, 2011. Xelerance <http://www.xelerance.com/>.

""" Easy DNS (including DNSSEC) via ldns.

In many respects, ldns is a great library. It is a powerfull tool for working with DNS. Unfortunatly, while it has python bindings, they are deeply lacking -- a thin, incomplete wrapper around the C library. The documentation is incomplete, functions don't work as described, some objects don't a full python API. Furthermore, it is a straight up clone of the C interface, which often isn't a very good interface for python. All this leads to a difficult to use library.

ldnsx aims to fix this. It wraps around the ldns python bindings, working around its limitations and providing a well-documented, more pythonistic interface.

EXAMPLES:

Ask the default nameserver for the A resource records for google.com

>>> import ldnsx
>>> resolver = ldnsx.resolver()
>>> for rr in resolver.query("google.com","A"):
>>>     print rr

Ask f.root-servers.net for the DS records for .com:

>>> import ldnsx
>>> resolver = ldnsx.resolver("f.root-servers.net")
>>> for rr in resolver.query("com.","DS"):
>>>     print rr

UNIT TESTS:

Writing unit tests for a DNS library is somewhat tricky since results generally depend on web servers, but here are a few:

>>> import ldnsx
>>> res = ldnsx.resolver("192.168.1.1")
>>> res.add_nameserver("192.168.1.2")
>>> res.add_nameserver("192.168.1.3")
>>> res.nameservers_ip()
["192.168.1.1","192.168.1.2","192.168.1.3"]

"""

import time, sys
try:
	import ipcalc
except ImportError:
	print >> sys.stderr, "ldnsx requires the python-ipcalc"
	print >> sys.stderr, "Fedora/CentOS: yum install python-ipcalc"
	print >> sys.stderr, "Debian/Ubuntu: apt-get install python-ipcalc"
	print >> sys.stderr, "openSUSE: zypper in python-ipcalc"
	sys.exit(1)
try:
	import ldns
except ImportError:
	print >> sys.stderr, "ldnsx requires the ldns-python sub-package from http://www.nlnetlabs.nl/projects/ldns/"
	print >> sys.stderr, "Fedora/CentOS: yum install ldns-python"
	print >> sys.stderr, "Debian/Ubuntu: apt-get install python-ldns"
	print >> sys.stderr, "openSUSE: zypper in python-ldns"
	sys.exit(1)

def isValidIP(ipaddr):
	try:
		bits = len(ipcalc.IP(ipaddr).bin())
	except:
		return 0
	if bits == 32:
		return 4
	elif bits == 128:
		return 6
	else:
		return 0

_rr_types={
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
	
	def __init__(self, ns = None, dnssec=False):
		"""resolver constructor
			
			  * ns -- the nameserver/comma delimited nameserver list
			          defaults to settings from /etc/resolv.conf

			EXAMPLES:

			>>> resolver() # from /etc/resolv.conf
			>>> resolver("") # resolver with no nameservers
			>>> resolver("193.110.157.135") #resolver pointing to ip addr
			>>> resolver("f.root-servers.net") # resolver pointing ip address(es) resolved from name
			>>> resolver("193.110.157.135, 193.110.157.136") 
			>>> # resolver pointing to multiple ip addr, first takes precedence.

			"""
		# We construct based on a file and dump the nameservers rather than using
		# ldns_resolver_new() to avoid environment/configuration/magic specific 
		# bugs.
		self._ldns_resolver = ldns.ldns_resolver.new_frm_file("/etc/resolv.conf")
		if ns != None:
			self.drop_nameservers()
			nm_list = ns.split(',')
			nm_list.reverse()
			for nm in nm_list:
				self.add_nameserver(nm)
		self.set_dnssec(dnssec)

	
	def query(self, name, rr_type, dns_class="IN", tries = 1):
		"""Run a query on the resolver.
			
			  * name -- name to query for
			  * rr_type -- the record type to query for (see suported_rr_types)
			  * dns_class -- the class to query for, defaults to IN (Internet)
			  * tries -- the number of times to attempt to acheive query in case of packet loss, etc

			EXAMPLE:

			>>> for rr in resolver.query("google.com","A")
			>>>     print rr


		"""
		if not rr_type in _rr_types.keys():
			raise Exception("Unknown DNS Record Type")
		if tries == 0: return None
		pkt = self._ldns_resolver.query(name, _rr_types[rr_type], ldns.LDNS_RR_CLASS_IN)
		if not pkt:
			time.sleep(1)
			return self.query(name, rr_type, dns_class=dns_class, tries = tries-1) 
		return packet(pkt)
		#ret = []
		#for rr in pkt.answer().rrs():
		#	ret.append([str(rr.owner()),rr.ttl(),rr.get_class_str(),rr.get_type_str()]+[str(rdf) for rdf in rr.rdfs()])
		#return ret
	
	def suported_rr_types(self):
		""" Returns the supported DNS resource record types.

			Refer to http://www.iana.org/assignments/dns-parameters
			section Resource Record (RR) TYPEs or to
			https://secure.wikimedia.org/wikipedia/en/wiki/List_of_DNS_record_types

			Note that these are record types supported by the resolver. It is possible that
			the nameserver might not support them.

		"""
		return _rr_types.keys()
	
	def AXFR(self,name):
		"""AXFR for name
			
			This function is a generator. As it AXFRs it will yield you the records.

		"""
		#Dname seems to be unecessary on some computers, but it is on others. Avoid bugs.
		if self._ldns_resolver.axfr_start(ldns.ldns_dname(name), ldns.LDNS_RR_CLASS_IN) != ldns.LDNS_STATUS_OK:
			raise Exception("Starting AXFR failed. Error: %s" % ldns.ldns_get_errorstr_by_id(status))
		pres = self._ldns_resolver.axfr_next()
		while pres:
			yield resource_record(pres)
			pres = self._ldns_resolver.axfr_next()

	def nameservers_ip(self):
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
		""" Add a nameserver, IPv4/IPv6/name.

		"""
		if isValidIP(ns) == 4:
			address = ldns.ldns_rdf_new_frm_str(ldns.LDNS_RDF_TYPE_A,ns)
			self._ldns_resolver.push_nameserver(address)
		elif isValidIP(ns) == 6:
			address = ldns.ldns_rdf_new_frm_str(ldns.LDNS_RDF_TYPE_AAAA,ns)
			self._ldns_resolver.push_nameserver(address)
		else:
			resolver = ldns.ldns_resolver.new_frm_file("/etc/resolv.conf")
			address = resolver.get_addr_by_name(ns)
			if not address:
				raise Exception("Failed to resolve address")
			for rr in address.rrs():
				self._ldns_resolver.push_nameserver_rr(rr)

	def drop_nameservers(self):
		"""Drops all nameservers.
			This function causes the resolver to forget all nameservers.

		"""
		while self._ldns_resolver.pop_nameserver():
			pass

	def set_nameservers(self, nm_list):
		self.drop_nameservers()
		for nm in nm_list:
			self.add_nameserver(nm)

	def __repr__(self):
		return "<resolver: %s>" % ", ".join(self.nameservers_ip())
	__str__ = __repr__

	def set_dnssec(self,new_dnssec_status):
		self._ldns_resolver.set_dnssec(new_dnssec_status)


class packet:
	
	def __init__(self, pkt):
		self._ldns_pkt = pkt
	
	def __repr__(self):
		return str(self._ldns_pkt)
	__str__ = __repr__
	
	def rcode(self):
		"""Returns the rcode.

		Example returned value: "NOERROR"

		possilbe rcodes (via ldns): "FORMERR", "MASK", "NOERROR",
		"NOTAUTH", "NOTIMPL", "NOTZONE", "NXDOMAIN",
		"NXRSET", "REFUSED", "SERVFAIL", "SHIFT", 
		"YXDOMAIN", "YXRRSET"

		Refer to http://www.iana.org/assignments/dns-parameters
		section: DNS RCODEs
		"""
		return self._ldns_pkt.rcode2str()

	def opcode(self):
		"""Returns the rcode.

		Example returned value: "QUERY"

		"""
		return self._ldns_pkt.opcode2str()
	
	def flags(self):
		"""Return packet flags (as list of strings).
		
		Example returned value: ['QR', 'RA', 'RD']
		
		From http://www.iana.org/assignments/dns-parameters:

		>  Bit       Flag  Description            Reference
		>  --------  ----  ---------------------  ---------
		>  bit 5     AA    Authoritative Answer   [RFC1035]
		>  bit 6     TC    Truncated Response     [RFC1035]
		>  bit 7     RD    Recursion Desired      [RFC1035]
		>  bit 8     RA    Recursion Allowed      [RFC1035]
		>  bit 9           Reserved
		>  bit 10    AD    Authentic Data         [RFC4035]
		>  bit 11    CD    Checking Disabled      [RFC4035]

		There is also QR. It is mentioned in other sources,
		though not the above page. It being false means that
		the packet is a query, it being true means that it is
		a response.

		"""
		ret = []
		if self._ldns_pkt.aa(): ret.append("AA")
		if self._ldns_pkt.ad(): ret.append("AD")
		if self._ldns_pkt.cd(): ret.append("CD")
		if self._ldns_pkt.qr(): ret.append("QR")
		if self._ldns_pkt.ra(): ret.append("RA")
		if self._ldns_pkt.rd(): ret.append("RD")
		if self._ldns_pkt.tc(): ret.append("TC")
		return ret

	def answer(self):
		"""Returns the answer section.
		"""
		return [resource_record(rr) for rr in self._ldns_pkt.answer().rrs()]

	def authority(self):
		"""Returns the authority section.
		"""
		return [resource_record(rr) for rr in self._ldns_pkt.auhtority().rrs()]

	def additional(self):
		"""Returns the additional section.
		"""
		return [resource_record(rr) for rr in self._ldns_pkt.additional().rrs()]

	def question(self):
		"""Returns the question section.
		"""
		return [resource_record(rr) for rr in self._ldns_pkt.question().rrs()]

class resource_record:
	def __init__(self, rr):
		self._ldns_rr = rr
	
	def __repr__(self):
		return str(self._ldns_rr)
	
	__str__ = __repr__
	
	def owner(self):
		return str(self._ldns_rr.owner())
	
	def rr_type(self):
		return self._ldns_rr.get_type_str()
	
	def ip(self):
		if self.rr_type() in ["A", "AAAA"]:
			return str(self._ldns_rr.rdfs().next())
		else:
			#raise Exception("ldnsx does not support ip for records other than A/AAAA")
			return "" #More convenient as an interface, in practice

	


