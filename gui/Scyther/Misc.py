"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007 Cas Cremers

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
    from subprocess import Popen,PIPE
except:
    panic("""
Cannot import 'subprocess.Popen' module. 

You need at least Python 2.4 to use this program.
""")

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


# ensurePath: wraps os.makedirs
def ensurePath(pt):
    """
    Make sure the path exists: if not, create the directories one by one

    By example:

    Call with "dog/cat/bone" ensures that afterwards, this subdirectory structure (dog/cat/bone) exists, with 'bone' a directory.
    It ensures this by doing the procedure for "dog", then "dog/cat", etc...
    """

    if not os.path.isdir(pt):
         # Note that os.path.exists(pt) may still hold. In this case the next command will cause an error.
         os.makedirs(pt)


# path
def mypath(file):
    """ Construct a file path relative to the scyther-gui main directory
    """
    basedir = os.path.dirname(__file__)
    return os.path.join(basedir,file)

def getShell():
    """
    Determine if we want a shell for Popen
    """
    if sys.platform.startswith("win"):
        shell=False
    else:
        # Needed to handle the string input correctly (as opposed to a sequence where the first element is the executable)
        # This is not needed on Windows, where it has a different effect altogether.
        # See http://docs.python.org/library/subprocess.html?highlight=subprocess#module-subprocess
        shell=True
    return shell

def safeCommandOutput(cmd):
    """ Execute a command and return (sts,sout,serr).
    Meant for short outputs, as output is stored in memory and
    not written to a file.
    """
    p = Popen(cmd, shell=getShell(), stdout=PIPE, stderr=PIPE)
    (sout,serr) = p.communicate()

    return (p.returncode,sout,serr)

def safeCommand(cmd):
    """ Execute a command with some arguments. Safe cross-platform
    version, I hope. """

    p = Popen(cmd, shell=getShell())
    sts = p.wait()

    return sts

def panic(text):
    """
    Errors that occur before we even are sure about wxPython etc. are dumped
    on the command line and reported using Tkinter.
    """

    import Tkinter
    
    print text

    root = Tkinter.Tk()
    w = Tkinter.Label(root, text=text)
    w.pack()
    root.mainloop()

    sys.exit(-1)

