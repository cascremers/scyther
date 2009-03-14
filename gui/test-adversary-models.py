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

import sys
import commands
from optparse import OptionParser

from adversaries import main

def isEmpty(cmd):
    """
    Check what comes back.
    """
    out = commands.getoutput(cmd)
    if len(out.splitlines()) == 0:
        return True
    else:
        return False

def filterSymmetric(protfile):
    return isEmpty("grep -l \"\<sk\>\|\<pk\>\" %s" % (protfile))

def filterAsymmetric(protfile):
    return isEmpty("grep -L \"\<sk\>\|\<pk\>\" %s" % (protfile))

def initParser():
    """
    Init the main parser.
    """

    parser = OptionParser()

    #parser.add_option("-f", "--file", dest="filename",
    #                  help="write report to FILE", metavar="FILE")
    #parser.add_option("-q", "--quiet",
    #                  action="store_false", dest="verbose", default=True,
    #                  help="don't print status messages to stdout")

    parser.add_option("-m","--models", action="store", dest="models", help="Consider adversary models by name.", metavar="ID", default="CSF09")
    parser.add_option("-d","--dir", action="append", dest="dirs", help="Set directories to scan for protocols.", metavar="PATH")
    parser.add_option("-a","--asymmetric", action="store_true", dest="asymmetric", help="Filter to assymetric crypto only.", default=False)
    parser.add_option("-s","--symmetric", action="store_true", dest="symmetric", help="Filter to ssymetric crypto only.", default=False)
    parser.add_option("","--PSH", action="append_const", const="psh", dest="graphs", help="Generate protocol-security hierarchy.")
    parser.add_option("","--MH",  action="append_const", const="mh",  dest="graphs", help="Generate adversary-model hierarchy.")
    parser.add_option("","--CH",  action="append_const", const="ch",  dest="graphs", help="Generate detailed combined hierarchy.")
    parser.add_option("-g","--graphs", action="store_const", const=["psh","mh","ch"],  dest="graphs", help="Generate all graphs.")
    parser.add_option("-A","--authentication", action="store_const", const="authentication",  dest="claimfilter", help="Restrict to authentication claims.")
    parser.add_option("-S","--secrecy", action="store_const", const="secrecy",  dest="claimfilter", help="Restrict to secrecy claims.")
    parser.add_option("-M","--modulo", action="store", dest="modulo", metavar="\"(MOD,IDX)\"", help="Only consider protocol claims for which (count % MOD) == IDX")
    parser.add_option("","--cache-transitive-closure", action="store_const", const=True,  dest="closecache", default=False, help="Compute transitive closure of cached verification data.")
    parser.add_option("-D","--debug", action="store_const", const=True,  dest="debug", default=False, help="Display debugging information.")

    (options, args) = parser.parse_args()
    return (options, args)


if __name__ == '__main__':
    # Options
    (options, args) = initParser()

    # Symmetric/asymmetric filters
    filefilter = None
    if options.symmetric:
        if options.asymmetric:
            print "Error: cannot use filter for symmetric and asymmetric at once."
            sys.exit()
    if options.symmetric:
        filefilter = filterSymmetric
    if options.asymmetric:
        filefilter = filterAsymmetric

    # Base dir
    protocolpaths = ["Protocols/AdversaryModels"]
    if options.dirs != None:
        if len(options.dirs) > 0:
            protocolpaths = []
            for dir in options.dirs:
                while dir.endswith("/"):
                    dir = dir[:-1]
                protocolpaths.append(dir)

    # Name list


    # Call main 
    main(models=options.models, protocolpaths=protocolpaths, filefilter=filefilter, graphs=options.graphs, debug=options.debug, closecache=options.closecache, modulo=options.modulo, options=options)


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
