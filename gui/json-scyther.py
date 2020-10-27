#!/usr/bin/env python
"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2013 Cas Cremers

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

Author: Cas Cremers

"""

import sys
import json
from Scyther import Scyther


def scyther_json(jsondata):
    """
    Decode json data into (protocollist,options,filter) and run scyther
    """
    s = Scyther.Scyther()

    (protocollist,options,filter) = json.loads(jsondata)

    s.options = str(options)
    for protocol in sorted(protocollist):
        s.addFile(protocol)
    s.verifyOne(str(filter))

def fileandline(fn,linenos):
    fp = open(fn,"r")
    ln = 1
    done = 0
    sz = len(linenos)
    for l in fp:
        if str(ln) in linenos:
            print(l)
            scyther_json(l)
            done = done + 1
            if done >= sz:
                fp.close()
                return
        ln = ln + 1
    fp.close()
    return

if __name__ == '__main__':
    fileandline(sys.argv[1],set(sys.argv[2:]))

    
