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

Dummy.

Author: Cas Cremers

"""

class ProgressBar(object):

    def __init__(self,widgets=[],maxval=100):
        self.widgets = widgets
        self.maxval = maxval

    def start(self):
        if self.widgets:
            if len(self.widgets) > 0:
                print(self.widgets[0], end=' ')

    def update(self,count):
        pass

    def finish(self):
        print(" Done.")


def SimpleProgress():
    return

def ETA():
    return

def Percentage():
    return

def Bar(marker,left,right):
    return

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
