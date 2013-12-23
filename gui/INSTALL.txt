Installation and usage of the Scyther tool
==========================================

Requirements
------------

To be able to use Scyther, you need the following three things:


1. The GraphViz library.

  This library is used by the Scyther tool to draw graphs. It can be
  freely downloaded from:

	http://www.graphviz.org/

  Download the latest stable release and install it.



The graphical user interface of Scyther is written in the Python
language. Therefore, the GUI requires the following two items:


2. Python 

  Stable releases of the Python interpreter are available from:

  	<a href="http://www.python.org/download/">

  Scyther does not support Python 3. You are therefore recommended to
  choose the latest production release of Python 2, e.g., Python 2.7.

  Mac OS X:
  	If the package yields an error when you try to install it,
  	please use the following, in the directory where you downloaded
  	it:
  	
  	 $ sudo installer -pkg graphviz-2.34.0.pkg -target /


3. wxPython libraries.

  The GUI user interface uses the wxPython libraries.

	<a href="http://www.wxpython.org/download.php">

  There are many different wxPython packages. You should choose a 32-bit
  package that matches your Python version (e.g., 2.7). It is
  recommended to select the unicode version from the stable releases.

  As of writing (May 2013) the following links lead to the appropriate
  wxPython packages for Python 2.7:

  Windows:
  	<a href="http://downloads.sourceforge.net/wxpython/wxPython2.8-win32-unicode-2.8.12.1-py27.exe">

  Mac OS X:
  	<a href="http://downloads.sourceforge.net/wxpython/wxPython2.8-osx-unicode-2.8.12.1-universal-py2.7.dmg">

	Note that this package is in an old format and you will probably
	get a warning "Package is damaged". This can be resolved by:
  	
  	 $ sudo installer -pkg /Volume/.../wxPython2.8-osx-unicode-universal-py2.7.pkg/ -target /

  Ubuntu/Debian Linux:
  	<a href="http://wiki.wxpython.org/InstallingOnUbuntuOrDebian">


Running Scyther
---------------


Start Scyther by executing the file

  	scyther-gui.py

in the directory where you found this file.

  Mac OS X:
  
    Right-click the file 'scyther-gui.py' and select "Open with" and
    then "Python Launcher".


