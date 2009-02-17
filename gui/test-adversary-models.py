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
    parser.add_option("-d","--dir", action="store", dest="dir", help="Set base directory to scan for protocols.", metavar="PATH", default = "Protocols/AdversaryModels")
    (options, args) = parser.parse_args()

    return (options, args)


if __name__ == '__main__':
    # Options
    (options, args) = initParser()

    # Base dir
    if options.dir != None:
        protocolpath = options.dir
        while protocolpath.endswith("/"):
            protocolpath = protocolpath[:-1]

    # Call main 
    main(models=options.models, protocolpath=protocolpath)


# vim: set ts=4 sw=4 et list lcs=tab\:>-:
