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

import commands

from adversaries import main

if __name__ == '__main__':
    # Compute list of adversary models for test
    cmd = "ls -1 Protocols/AdversaryModels/*.spdl"
    ll = commands.getoutput(cmd)
    nl = []
    for fn in ll.splitlines():
        xd = fn.split("/")
        res = xd[-1].rstrip()
        pref = res.split(".")[0]
        nl.append(pref)
    # Call main with None to do all
    main(protocollist=nl)


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
