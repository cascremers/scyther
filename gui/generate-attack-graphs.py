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

"""
Generate attacks for each claim

To also generate resource usage details on linux, use something like:

    xargs -a protocols.txt -n 1 -I {} /usr/bin/time -v -o {}.times ./generate-attack-graphs.py {}

where 'protocols.txt' contains a protocol file per line.
"""

#---------------------------------------------------------------------------

""" Import externals """
import sys

#---------------------------------------------------------------------------

""" Import scyther components """
import Scyther.Scyther as Scyther

#---------------------------------------------------------------------------

def create_file_prefix(fn,cid):
    """
    Create a filename prefix for fn,cid without extension
    """

    tcid = cid
    i = tcid.rfind(",")
    if i > 0:
        if fn.find(tcid[:i]) >= 0:
            tcid = tcid[i+1:]

    tfn = fn.replace(".spdl","")
    i = tfn.rfind("/")
    if i >= 0:
        tfn = tfn[i+1:]

    pref = "%s-%s" % (tfn,tcid)
    pref = pref.replace(",","_")

    return pref


def render_dot(fn,gtype):
    """
    Render .dot file called fn into gtype file
    """
    from subprocess import call

    if len(gtype) > 5:
        # Something is fishy, abort
        return

    base_name = fn
    i = base_name.rfind(".")
    if i > 0:
        base_name = base_name[:i]

    cmd = ["dot","-T" + gtype,"-o%s.%s" % (base_name,gtype),fn]
    #print cmd

    call(cmd)


def render_best_attack(fn,cid):
    """
    Extract the best attack for this claim and file name
    """
    x = Scyther.Scyther()
    x.setFile(fn)

    x.options = "-r4 -T60"
    x.verifyOne(cid)

    pref = create_file_prefix(fn,cid)

    for cl in x.claims:
        cln = cl.claimtype
        if cln == "Commit":
            cln = "Data_agree"

        if len(cl.attacks) > 0:
            dotfile = "attack-%s-%s.dot" % (pref,cln)
            fp = open(dotfile,'w')
            fp.write(cl.attacks[-1].scytherDot)
            fp.close()

            render_dot(dotfile,"png")
            render_dot(dotfile,"pdf")

        print("%s; %s" % (fn,cl))

def main():

    filelist = sys.argv[1:]
    # Compute dict of filenames to claim id's
    cl = Scyther.GetClaims(filelist)
    
    for fn in set(cl):
        for cid in cl[fn]:

            render_best_attack(fn,cid)



if __name__ == '__main__':
    main()

#---------------------------------------------------------------------------
# vim: set ts=4 sw=4 et list lcs=tab\:>-:
