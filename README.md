The Scyther tool repository
===========================

This README describes the organization of the repository of the Scyther
tool for security protocol analysis. Its intended audience are
interested users and future developers of the Scyther tool, as well as
protocol modelers. For installation and usage instructions of the
Scyther tool see:
<http://www.cs.ox.ac.uk/people/cas.cremers/scyther/index.html>.

Installing from source
----------------------

We use Linux during the development of Scyther, but development on
Windows and MAC OS X should be equally feasible. Note that the below
instructions are written from a Linux/Ubuntu perspective, and probably
need modifications for other platforms.

Scyther is written partly in Python 2 (for the GUI, using wxPython) and
partly in C (for the backend). 

In order to run the tool from a repository checkout, it is required to
compile the C sources into a working binary for the backend.  The
simplest way to achieve this is to run the `build.sh` script in the
`./src` directory. This script compiles a binary version of the tool on
the native platform. Thus, in the Linux case, it should produce
`./src/scyther-linux`. This file is automatically copied to the related
directory under `./gui`, and if successful you can attempt to run
`./gui/scyther-gui.py` to use the graphical user interface.

The build process depends on the following
(Debian/Ubuntu) packages:

  * `cmake`
  * `build-essential`
  * `flex`
  * `bison`
  * `gcc-multilib`
  * `python-minimal`

If you are using Ubuntu, installing these may be as simple as running

`sudo apt-get install cmake build-essential flex bison gcc-multilib python-minimal`

In case you also want to be able to compile Windows binaries from Linux,
you also need:

  * `mingw32`

Note that welcome all contributions, e.g., further protocol models. Just send
us a pull request.


Manual
------

We are currently rewriting the manual. The current (incomplete) snapshot
of the manual can be found in the following location:

  * [./gui/scyther-manual.pdf](gui/scyther-manual.pdf)


Protocol Models
---------------

The protocol models have the extension `.spdl` and can be found in the following directories:

  * [./gui/Protocols](gui/Protocols), containing the officially released models, and
  * [./testing](testing), containing models currently under development.

License
-------

Currently these Scyther sources are licensed under the GPL 2, as indicated in
the source code. Contact Cas Cremers if you have any questions.

