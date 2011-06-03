Welcome to ldnsx's documentation!
=================================

LDNSX: Easy DNS (including DNSSEC) via ldns.

ldns is a great library. It is a powerfull tool for
working with DNS. python-ldns it is a straight up clone of the C
interface, howver that is not a very good interface for python. Its
documentation is incomplete and some functions don't work as
described. And some objects don't have a full python API.

ldnsx aims to fix this. It wraps around the ldns python bindings,
working around its limitations and providing a well-documented, more
pythonistic interface.

Contents:

.. toctree::
   :maxdepth: 2
   
   api/ldnsx

* .. toctree::
   :maxdepth: 1

   api/resolver
   api/packet
   api/resource_record


Indices and tables
==================

* :ref:`genindex`
* :ref:`search`

