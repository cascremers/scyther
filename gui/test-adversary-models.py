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

import sys
import time
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
    """
    The filter should return true to select, false to reject.
    """
    return isEmpty("grep -l \"\<sk\>\|\<pk\>\" %s" % (protfile))

def filterAsymmetric(protfile):
    """
    The filter should return true to select, false to reject.
    """
    return isEmpty("grep -L \"\<sk\>\|\<pk\>\" %s" % (protfile))

def filterString(protfile,filterstring):
    """
    Returns true to select, i.e. txt does not occur as substring
    """
    if protfile.find(filterstring) >= 0:
        print "Ignoring '%s' because it contains an ignored substring '%s'" % (protfile,filterstring)
        return False
    else:
        return True

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

    parser.add_option("-m","--models", action="store", dest="models", help="Consider adversary models by name.", metavar="ID", default="paper")
    parser.add_option("","--max-runs", action="store", dest="maxruns", help="Bound maximum number of runs.", metavar="INT", default="5")
    parser.add_option("-d","--dir", action="append", dest="dirs", help="Set directories to scan for protocols.", metavar="PATH")
    parser.add_option("-a","--asymmetric", action="store_true", dest="asymmetric", help="Filter to asymmetric crypto only.", default=False)
    parser.add_option("","--ignore", action="append", dest="ignore", help="Ignore file names with this substring.", metavar="STRING")
    parser.add_option("-s","--symmetric", action="store_true", dest="symmetric", help="Filter to symmetric crypto only.", default=False)
    parser.add_option("","--PSH", action="append_const", const="psh", dest="graphs", help="Generate protocol-security hierarchy.")
    parser.add_option("","--MH",  action="append_const", const="mh",  dest="graphs", help="Generate adversary-model hierarchy.")
    parser.add_option("","--CH",  action="append_const", const="ch",  dest="graphs", help="Generate detailed combined hierarchy.")
    parser.add_option("-l","--label", action="store", dest="label", help="Add label to output graph.")
    parser.add_option("-g","--graphs", action="store_const", const=["psh","mh","ch"],  dest="graphs", help="Generate all graphs.")
    parser.add_option("-A","--authentication", action="store_const", const="authentication",  dest="claimfilter", help="Restrict to authentication claims.")
    parser.add_option("-S","--secrecy", action="store_const", const="secrecy",  dest="claimfilter", help="Restrict to secrecy claims.")
    parser.add_option("-M","--modulo", action="store", dest="modulo", metavar="\"(MOD,IDX)\"", help="Only consider protocol claims for which (count % MOD) == IDX")
    parser.add_option("","--cache-transitive-closure", action="store_const", const=True,  dest="closecache", default=False, help="Compute transitive closure of cached verification data.")
    parser.add_option("-D","--debug", action="store_const", const=True,  dest="debug", default=False, help="Display debugging information.")
    parser.add_option("","--paper", action="store_const", const=True, dest="paper", default=False, help="Repeat experiments as in paper.")
    parser.add_option("","--paper-protocols", action="store_const", const=True, dest="paperprotocols", default=False, help="Add protocols from paper.")
    parser.add_option("","--no-buffer", action="store_const", const=True, dest="nobuffer", default=False, help="Do not write large verification file cache.")

    (options, args) = parser.parse_args()
    return (options, args)


def pathAdd(paths, args):
    if args != None:
        if len(args) > 0:
            for dir in args:
                while dir.endswith("/"):
                    dir = dir[:-1]
                paths.append(dir)
    return paths


def protocolListPaper():
    return [ \
        "Protocols/AdversaryModels/2DH-ISO-C.spdl", \
        "Protocols/AdversaryModels/2DH-ISO.spdl", \
        "Protocols/AdversaryModels/BKE.spdl", \
        "Protocols/AdversaryModels/DHKE-1.spdl", \
        "Protocols/AdversaryModels/HMQV-C.spdl", \
        "Protocols/AdversaryModels/HMQV-twopass.spdl", \
        "Protocols/AdversaryModels/kea-plus.spdl", \
        "Protocols/AdversaryModels/MQV-twopass.spdl", \
        "Protocols/AdversaryModels/naxos.spdl", \
        "Protocols/AdversaryModels/ns3.spdl", \
        "Protocols/AdversaryModels/nsl3.spdl", \
        "Protocols/AdversaryModels/yahalom-ban-paulson-modified.spdl", \
        "Protocols/AdversaryModels/yahalom-ban-paulson.spdl" \
        ]


if __name__ == '__main__':
    # Store command line in log
    commands.getoutput("echo \"[%s]\t%s\" >>test.log" % (time.ctime()," ".join(sys.argv)))

    # Options
    (options, args) = initParser()

    # Init filters
    filefilters = []

    # Symmetric/asymmetric filters
    if options.symmetric:
        if options.asymmetric:
            print "Error: cannot use filter for symmetric and asymmetric at once."
            sys.exit()
    if options.symmetric:
        filefilters.append(filterSymmetric)
    if options.asymmetric:
        filefilters.append(filterAsymmetric)

    # Removing files
    if options.ignore != None:
        for ign in options.ignore:
            import functools

            filefilters.append(functools.partial(filterString,filterstring=ign))

    protocolpaths = []

    # Paper protocols?
    if options.paperprotocols:
        protocolpaths += protocolListPaper()

    # Add paths to dirs
    protocolpaths = pathAdd(protocolpaths, options.dirs)

    # Any additional args are considered similar to -d (protocolpath) options.
    protocolpaths = pathAdd(protocolpaths, args)

    # Override by default
    if len(protocolpaths) == 0:
        protocolpaths = ["Protocols/AdversaryModels"]

    # Paper settings for repeating the experiments
    if options.paper:
        protocolpaths = protocolListPaper()
        options.models = "paper"
        options.graphs = ["psh","mh","ch"]

    # Write back
    options.dirs = protocolpaths

    # Call main 
    main(models=options.models, protocolpaths=protocolpaths, filefilters=filefilters, graphs=options.graphs, debug=options.debug, closecache=options.closecache, modulo=options.modulo, options=options)


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
