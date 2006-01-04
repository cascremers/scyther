------------------------------------------------------------------------

				Scyther

	       a verification tool for security protocols
			     by Cas Cremers

------------------------------------------------------------------------


Note: This is a 1.0beta release, and therefore the usual warnings apply.



1. More information
========================================================================

For more information, see:

  http://www.win.tue.nl/~ccremers/scyther


2. Starting out
========================================================================

To start, run the scyther executable (scyther/scyther) with the --help
switch, or try

  $ scyther/scyther demo/ns3.spdl

For graphical output, you need:

- a pdf viewer (xpdf is assumed)
- the GraphViz package (for the 'dot' executable).

Add the paths 'scyther/' and 'demo/' to your path environment variable
(something like 'export PATH=$PATH:$PWD/demo'), and try

  $ scytherview demo/nsl3.spdl


3. Citing Scyther
===========================

For now, there is no official journal paper to cite yet, but you can use
the following information:

@misc{wwwscyther,
  Author = "C.J.F. Cremers",
  Title  = "Scyther security protocol verification tool: documentation",
  Note   = "\url{http://www.win.tue.nl/~ccremers/scyther}",
  url    = "http://www.win.tue.nl/~ccremers/scyther"
}

