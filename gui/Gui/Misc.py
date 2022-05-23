"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2020 Cas Cremers

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
from subprocess import Popen,PIPE,run
from shlex import quote

""" Import scyther components """
from Scyther import FindDot

""" Import scyther-gui components """
from . import Temporary

#---------------------------------------------------------------------------

def confirm(question):
    answer = ''
    while answer not in ('y','n'):
        print(question, end=' ')
        answer = input().lower()
    return answer == 'y'

def exists(func,list):
    return len(list(filter(func,list))) > 0    

def forall(func,list):
    return len(list(filter(func,list))) == len(list)    

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

# Write string to tempfile, return (filedescriptor,name)
def stringToTempfile(data,ext="tmp"):
    """
    Take data (a string) and write it to a safe temporary file.
    Return the resulting filedescriptor and name as a pair.
    """
    (fd,fpname) = Temporary.tempcleaned(ext)
    f = os.fdopen(fd,'w')
    f.write(data)
    f.close()

    return (fd, fpname)


# commands: push data in as file named argument to dot, get fp.write out
def dotOutputWrite(data,fname,cmd=[]):
    """
    Feed stdin data to cmd array, write the output to a freshly
    created file 'fname'. The file is flushed and closed at the end.

    TODO: In reality, this particular dot data was already written to another temp file when rendering the attack graph. We should be reusing that file instead of writing a new one.
    """
    (fd_in,fpname_in) = stringToTempfile(data,ext="dot")

    dotcommand = FindDot.findDot()
    execcmd = [dotcommand] + cmd + ["-o" + quote(fname), quote(fpname_in)]
    print (execcmd)

    # execute command
    run(execcmd)

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
