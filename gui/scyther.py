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

#
# python wrapper for the Scyther command-line tool
#

#---------------------------------------------------------------------------

""" Import externals """
import sys

#---------------------------------------------------------------------------

""" Import scyther components """
import Scyther.Scyther as Scyther

#---------------------------------------------------------------------------

def usage():
    x = Scyther.Scyther()
    x.xml = False
    x.options = "--help"
    x.verify()
    return x

def simpleRun(args):
    x = Scyther.Scyther()
    x.options = args
    x.verify()
    return x

if __name__ == '__main__':
    pars = sys.argv[1:]
    if len(pars) == 0:
        print usage()
    else:
        print simpleRun(" ".join(pars))


