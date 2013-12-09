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


#---------------------------------------------------------------------------

""" Import externals """
import wx
import os
import sys
from subprocess import Popen, PIPE

#---------------------------------------------------------------------------

""" Import scyther components """
from Scyther import Misc as MiscScyther
from Scyther import FindDot

""" Import scyther-gui components """
import Temporary
import Preference

#---------------------------------------------------------------------------
try:
    import Image
except ImportError:
    pass
#---------------------------------------------------------------------------


def writeGraph(attackthread,txt,fp):

    EDGE = 0
    NODE = 1
    DEFAULT = 2
    ALL = 3

    def graphLine(txt):
        fp.write("\t%s;\n" % (txt))

    def setAttr(atxt,EdgeNodeDefAll=ALL):
        if EdgeNodeDefAll == ALL:
            setAttr(atxt,EDGE)
            setAttr(atxt,NODE)
            setAttr(atxt,DEFAULT)
        else:
            if EdgeNodeDefAll == EDGE:
                edge = "edge"
            elif EdgeNodeDefAll == NODE:
                edge = "node"
            else:
                graphLine("%s" % atxt)
                return
            graphLine("%s [%s]" % (edge,atxt))

    if sys.platform.startswith("darwin"):
        attackthread.fontname = "Helvetica"
    elif sys.platform.startswith("win"):
        attackthread.fontname = "Courier"
    else:
        #font = wx.Font(9,wx.SWISS,wx.NORMAL,wx.NORMAL)
        #attackthread.fontname = font.GetFaceName()
        attackthread.fontname = "\"Helvetica\""

    # write all graph lines but add layout modifiers
    for l in txt.splitlines():
        fp.write(l)
        if l.startswith("digraph"):
            # Write additional stuff for this graph
            #
            # [CC][x] This dpi setting messed up quite a bit
            #graphLine("dpi=96")
            graphLine("rankdir=TB")
            #graphLine("nodesep=0.1")
            #graphLine("ranksep=0.001")
            #graphLine("mindist=0.1")

            # Set fontname
            if attackthread.fontname:
                fontstring = "fontname=%s" % (attackthread.fontname)
                setAttr(fontstring)

            # Stupid Mac <> Graphviz bug fix
            if (sys.platform.startswith("mac")) or (sys.platform.startswith("darwin")):
                # Note that dot on Mac cannot find the fonts by default,
                # and we have to set them accordingly.
                os.environ["DOTFONTPATH"]="~/Library/Fonts:/Library/Fonts:/System/Library/Fonts"

            # Select font size
            if attackthread.parent and attackthread.parent.mainwin:
                fontsize = attackthread.parent.mainwin.settings.fontsize
                setAttr("fontsize=%s" % fontsize)
            #setAttr("height=\"0.1\"",NODE)
            #setAttr("width=\"1.0\"",NODE)
            #setAttr("margin=\"0.3,0.03\"",NODE)


def makeImageDot(dotdata,attackthread=None):
    """ create image for this particular dot data """

    if Preference.usePIL():
        # If we have the PIL library, we can do postscript! great
        # stuff.
        type = "ps"
        ext = ".ps"
    else:
        # Ye olde pnge file
        type = "png"
        ext = ".png"

    # Retrieve dot command path
    dotcommand = FindDot.findDot()

    # command to write to temporary file
    (fd2,fpname2) = Temporary.tempcleaned(ext)
    f = os.fdopen(fd2,'w')

    # Set up command
    cmd = "%s -T%s" % (dotcommand,type)

    # execute command
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)


    if attackthread:
        writeGraph(attackthread,dotdata,p.stdin)
    else:
        p.stdin.write(dotdata)

    p.stdin.close()

    for l in p.stdout.read():
        f.write(l)

    p.stdout.close()
    f.flush()
    f.close()

    return (fpname2, type)


def makeImage(attack,attackthread=None):
    """ create image for this particular attack """

    """ This should clearly be a method of 'attack' """

    (name,type) = makeImageDot(attack.scytherDot,attackthread)
    # if this is done, store and report
    attack.file = name
    attack.filetype = type


def testImage():
    """
    We generate a postscript file from a dot file, and see what happens.
    """

    dotdata = "digraph X {\nA->B;\n}\n"
    (filename,filetype) = makeImageDot(dotdata)
    testimage = Image.open(filename)

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
