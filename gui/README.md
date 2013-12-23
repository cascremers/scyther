The Scyther tool
================

Scyther is a tool for the symbolic analysis of security protocols. It is
developed by Cas Cremers, and is available from
<http://www.cs.ox.ac.uk/people/cas.cremers/scyther/index.html>.

The below instructions apply only to the *distribution version* of
the Scyther tool. If you are working from the source files, some paths may be
slightly different, and it is recommended to follow the instructions in [../README.md](../README.md).

Running the scyther tool
------------------------

### Graphical user interface ###

The graphical user interface can be started by running `scyther-gui.py`,
e.g., enter the following in a terminal and press return

	python ./scyther-gui.py

### Command-line usage ###

In the directory `./Scyther` there should be an executable for the
Scyther backend. Its name depends on the platform:

 * `scyther-linux` (Linux)
 * `scyther-w32` (Windows)
 * `scyther-mac` (Mac OS X)

If this executable does not exist, you probably downloaded the source
files, and will need to compile it first. See `../README.md` for further
details.

There are also various test scripts (for usage in Linux) in this
directory.

Obtaining the sources
----------------------

Scyther is being developed on *Github*, and its complete source files are
availabe from
<https://github.com/cascremers/scyther>.

Manual
------

We are currently rewriting the manual. The current (incomplete)
distribution version of the manual can be found here:

  * [./scyther-manual.pdf](scyther-manual.pdf)


Protocol Models
---------------

The protocol models have the extension `.spdl` and can be found in the following directories:

  * [./Protocols](Protocols) and its subdirectories.

License
-------

Currently the Scyther tool is licensed under the GPL 2, as indicated in
the source code. Contact Cas Cremers if you have any questions.

