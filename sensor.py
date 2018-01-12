#!/usr/bin/env python
#
# Basic network intrusion detection sensor system by using AIEngine.
#
# Copyright (C) 2013-2018  Luis Campo Giralte
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
#
""" Example of using the pyaiengine """
import pyaiengine
import sys

st = pyaiengine.StackLan()

tcp_rm = pyaiengine.RegexManager()
udp_rm = pyaiengine.RegexManager()

""" Put here your code for load regexs 
    >>> tcp_rm.add_regex(pyaiengine.Regex("some regex", "\x00\x0a\x0b")
    >>> tcp_rm.add_regex(pyaiengine.Regex("some regex", "^\x00\x0a.*exe", callback)
"""

tcp_set = pyaiengine.IPSetManager()
udp_set = pyaiengine.IPSetManager()

tcp_ipset = pyaiengine.IPSet()
udp_ipset = pyaiengine.IPSet()

""" Put here your code with your IP lists
    >>> tcp_ipset.add_ip_address("192.158.1.1")
"""

http_names = pyaiengine.DomainNameManager()
ssl_names = pyaiengine.DomainNameManager()
dns_names = pyaiengine.DomainNameManager()

""" Put here your code with your domains for matching """
http_names.add_domain_name(pyaiengine.DomainName("Fedora", ".fedora.com"))
ssl_names.add_domain_name(pyaiengine.DomainName("Google", ".google.com"))
dns_names.add_domain_name(pyaiengine.DomainName("Google DNS", ".google.com"))

st.set_domain_name_manager(dns_names, "DNSProtocol")
st.set_domain_name_manager(http_names, "HTTPProtocol")
st.set_domain_name_manager(ssl_names, "SSLProtocol")

tcp_set.add_ip_set(tcp_ipset)
udp_set.add_ip_set(udp_ipset)

st.tcp_ip_set_manager = tcp_set
st.udp_ip_set_manager = udp_set
st.tcp_regex_manager = tcp_rm
st.udp_regex_manager = udp_rm

st.set_dynamic_allocated_memory(True)

with pyaiengine.PacketDispatcher("wlp4s0") as pd:
    pd.stack = st
    pd.enable_shell = True
    """ The interface will listen on port 3000 for the remote interface """
    pd.port = 3000 
    pd.run()


