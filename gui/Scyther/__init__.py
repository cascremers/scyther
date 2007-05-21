#
#   Init this module
#
#   The most important thing is to get the base directory right, in
#   order to correctly find the executables
#
import Scyther
import os.path

bindir = __path__[0]
Scyther.setBinDir(bindir)

