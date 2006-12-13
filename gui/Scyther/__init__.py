#
#   Init this module
#
#   The most important thing is to get the base directory right, in
#   order to correctly find the executables
#
import Scyther
import os.path

bindir = os.path.join(__path__[0],"Bin")
Scyther.setBinDir(bindir)
