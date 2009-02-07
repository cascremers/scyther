#!/usr/bin/python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2009 Cas Cremers

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""


"""

Example script to show how to perform large-scale tests using the
Scyther Python API (contained in the Scyther subdirectory)

In this example, compromise attacks.

Author: Cas Cremers

"""


import commands
import os

def getlist():
    cmd = "ls -1 ../../protocols/misc/compromise/*.spdl"
    ll = commands.getoutput(cmd)
    nl = []
    for fn in ll.splitlines():
        xd = fn.split("/")
        res = xd[-1].rstrip()
        pref = res.split(".")[0]
        nl.append(pref)

    nl.append("ns3.spdl")
    nl.append("nsl3.spdl")

    nl2 = []
    for fn in nl:
        if fn.find("TLS") != -1:
            continue
        if fn.find("BKE") != -1:
            continue
        nl2.append(fn)

    ### Override
    nl2 = ['2DH-ISO-C', 'BKE', '2DH-ISO', 
            'DHKE-1', 'HMQV-C',
            'HMQV-twopass', 'kea-plus', 
            'MQV-twopass', 'naxos', 
            'yahalom-ban-paulson-modified.spdl', 'yahalom-ban-paulson.spdl',
            'ns3.spdl', 'nsl3.spdl']
            #'2DH-ISO-specialK', 

    print nl2

    return nl2

cmd = "./test-compromise.py %s" % (" ".join(getlist()))
os.system(cmd)

