#!/usr/bin/python
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
# Convert scyther dot output to a printable PDF and display it
#
# This is a simple hack to be able to quickly use the graphical output
# of Scyther if one only has graphviz, but not elementtree and wxPython.
#
# Note 1: only works under Linux currently, because of silly assumptions
# on temporary directories and pdf viewers.
#
# Note 2: this code assumes that both scyther-linux and dot can be found in the
# environment (i.e. PATH variable)
#
import os,sys,subprocess
import os.path

tempcount = 0

def generateTemp(extension='tmp'):
    # We need a temporary file to hold the generated postscript stuff before
    # it is converted to pdf
    global tempcount

    tempcount = tempcount + 1
    tmp = '/tmp/output_dot_%s_%i.%s' % (os.getpid(),tempcount,extension)

    try:
        os.unlink(tmp)
    except:
        pass
    return tmp

def scyther_to_dotfile():
    """ Run Scyther, return dotfile name """

    mydir = os.path.dirname(__file__)
    scythername = os.path.join(mydir, "../Scyther/scyther-linux")

    args = " ".join(sys.argv[1:])
    tmpdotfile = generateTemp('dot')

    command = "%s --plain --dot-output %s > %s" % (scythername, args, tmpdotfile)
    output = subprocess.getoutput(command)
    return (output,tmpdotfile)

def dotfile_to_pdffile(dotfile,outfile=None):
    """ Generate a PDF file (name is returned) from an input dotfile
    name """

    tmp = generateTemp('ps')

    # First split the input per digraph and call dot with -Gsize arguments to make
    # it fit to a landscape page
    dotdata = open(dotfile, "r")
    f = None
    for line in dotdata:
        if (line.find('digraph') == 0):
            f = os.popen("dot -Gsize='11.0,8.0' -Gratio=fill -Tps >>%s" % (tmp),'w')
        print(line, file=f)
    dotdata.close()

    if not f:
        return None
    f.close()

    if not outfile:
        outfile = generateTemp('pdf')

    # Now convert the resulting stuff to a pdf
    os.system('ps2pdf -sPAPERSIZE=a4 -g7014x5300 -r600 %s %s' % (tmp,outfile))
    #os.system('ps2pdf -g8300x6250 -r600 %s %s' % (tmp,outf))

    # And remove the temp file
    os.unlink(tmp)

    return outfile

def main():
    (output,dotfile) = scyther_to_dotfile()
    print(output)
    pdffile = dotfile_to_pdffile(dotfile)
    os.unlink(dotfile)
    if pdffile:
        subprocess.getoutput("kpdf %s" % pdffile)
        os.unlink(pdffile)
    else:
        print("No graphs generated.")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main()
    else:
        print("Please provide the name of an input file.")

