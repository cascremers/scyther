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
# Misc.py
# Various helper functions

#---------------------------------------------------------------------------

""" Import externals """
import os.path
from subprocess import Popen,PIPE

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
    import os, inspect

    # Determine base directory (taking symbolic links into account)
    cmd_file = os.path.realpath(os.path.abspath(inspect.getfile( inspect.currentframe() )))
    basedir = os.path.split(cmd_file)[0]
    return os.path.join(basedir,file)

# commands: push data in, get fp.write out
def cmdpushwrite(cmd,data,fname):
    """
    Feed stdin data to cmd, write the output to a freshly created file
    'fname'. The file is flushed and closed at the end.
    """
    fp = open(fname,'w')
    # execute command
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
    (cin,cout) = (p.stdin, p.stdout)

    cin.write(data)
    cin.close()
    for l in cout.read():
        fp.write(l)
    cout.close()
    fp.flush()
    fp.close()

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
