------------------------------------------------------------------------

				Scyther

			       1.0-beta3

	       a verification tool for security protocols
			     by Cas Cremers

		 (Compiled for Linux i686 environments)

------------------------------------------------------------------------


Note: This is a BETA release, and therefore the usual warnings apply.



1. More information
========================================================================

For more information, see:

  http://www.win.tue.nl/~ccremers/scyther


2. Starting out
========================================================================

To start, untar the archive:

  $ tar zxvf scyther.tgz
  
This will produce a directory 'scyther'. Change into this directory.

  $ cd scyther

Now run the scyther executable (bin/scyther) with the --help switch,
or try:

  $ bin/scyther demo/ns3.spdl

To have Scyther produce graphical graphical output, you need:

- a pdf viewer (xpdf is assumed)
- the GraphViz package (for the 'dot' executable), which can be found
  at: http://www.research.att.com/sw/tools/graphviz/

Add the paths 'bin/' and 'demo/' to your path environment variable
(something like 'export PATH=$PATH:$PWD/bin:$PWD/demo'), and try

  $ scytherview demo/nsl3.spdl

Many other protocol input files can be found in the SPORE directory.


3. Citing Scyther
===========================

For now, there is no official journal paper to cite yet, but you can use
the following information:

@misc{wwwscyther,
  Author = "C.J.F. Cremers",
  Title  = "Scyther : Automated Verification of Security Protocols",
  Note   = "\url{http://www.win.tue.nl/~ccremers/scyther}",
  url    = "http://www.win.tue.nl/~ccremers/scyther"
}

