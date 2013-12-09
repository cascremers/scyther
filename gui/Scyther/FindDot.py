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
# FindDot.py
#
# Since version 2.31, GraphViz no longer sets the PATH environment variable on Windows.
# The sole reason of existence for this file is to solve this issue automatically if possible.

#---------------------------------------------------------------------------
""" Import externals """
import sys
import os
#---------------------------------------------------------------------------
""" Import internals """
import Misc
#---------------------------------------------------------------------------

DOTLOCATION = None

#---------------------------------------------------------------------------

def testDot(fpath):

    try:
        cmd = "%s -V" % (fpath)
        (sts,sout,serr) = Misc.safeCommandOutput(cmd)
        if sts != -1:
            if "version" in sout + serr:
                return True
    except:
        pass
    
    return False

#---------------------------------------------------------------------------

def scanPrefix(pf,name):

    if pf.endswith("*"):
        import glob

        gl = glob.glob(pf)
        for pf in gl:
            for root,dirs,files in os.walk(pf):
                for d in dirs:
                    npf = os.path.join(root,d)
                    res = scanPrefix(npf,name)
                    if res != None:
                        return res

        return None

    fpath = os.path.join(pf,name)
    if len(pf) > 0:
        fpath = "\"%s\"" % (fpath)
    if testDot(fpath) == True:
        return fpath

    return None


def scanLocations():
    if sys.platform.startswith("win"):
        prefixes = ["", \
                    "C:\Program Files\Graphviz*", \
                    "C:\Program Files (x86)\Graphviz*" ]
        name = "dot.exe"
    else:
        prefixes = [""]
        name = "dot"

    for pf in prefixes:
        path = scanPrefix(pf,name)
        if path != None:
            return path

    return None
    
#---------------------------------------------------------------------------

def findDot():
    global DOTLOCATION

    # Cache the results
    if DOTLOCATION != None:
        return DOTLOCATION

    DOTLOCATION = scanLocations()
    if DOTLOCATION == None:
        Misc.panic("""
Could not find the required 'dot' program, which is part of the Graphviz suite.
Please install it from http://www.graphviz.org/

Ubuntu users: install the 'graphviz' package.

Windows users: make sure that Graphviz is installed and 
   that the location of the 'dot' program is in
   the PATH environment variable.

Restarting your system may be needed for Scyther to locate any newly installed
programs.
        """)
    return DOTLOCATION

#---------------------------------------------------------------------------

if __name__ == '__main__':
    Misc.panic(findDot())

#---------------------------------------------------------------------------

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
