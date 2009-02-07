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

#
# Misc.py
# Various helper functions

#---------------------------------------------------------------------------

""" Import externals """
import sys
import os.path
try:
    from subprocess import Popen
    AvailablePopen = True
except:
    import os
    AvailablePopen = False

#---------------------------------------------------------------------------

def confirm(question):
    answer = ''
    while answer not in ('y','n'):
        print question,
        answer = raw_input().lower()
    return answer == 'y'

def exists(func,list):
    return len(filter(func,list)) > 0    

def forall(func,list):
    return len(filter(func,list)) == len(list)    

def uniq(li):
    result = []
    for elem in li:
        if (not elem in result):
            result.append(elem)
    return result

# Return a sorted copy of a list
def sorted(li):
    result = li[:]
    result.sort()
    return result


# path
def mypath(file):
    """ Construct a file path relative to the scyther-gui main directory
    """
    basedir = os.path.dirname(__file__)
    return os.path.join(basedir,file)

def safeCommand(cmd):
    """ Execute a command with some arguments. Safe cross-platform
    version, I hope. """

    global AvailablePopen

    if AvailablePopen:
        if sys.platform.startswith("win"):
            shell=False
        else:
            shell=True
        p = Popen(cmd, shell=shell)
        sts = p.wait()
    else:
        sts = os.system(cmd)

    return sts

