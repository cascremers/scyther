Installation and usage of the Scyther tool
==========================================

Requirements
------------

To be able to use all of Scyther's features, the following three
dependencies are needed. If you only require the back-end tool (used
from the command line) then you need only the first.

1. ### The GraphViz library ###

  This library is used by the Scyther tool to draw graphs. It can be
  freely downloaded from:

	http://www.graphviz.org/

  Download the latest stable release and install it.


2. ### Python ###

  Stable releases of the Python interpreter are available from:

  	http://www.python.org/download/

  Scyther does not support Python 3. You are therefore recommended to
  choose the latest production release of Python 2, e.g., Python 2.7.

  *	**Mac OS X**
  
  	If the package yields an error when you try to install it,
  	please use the following, in the directory where you downloaded
  	it:
  	
  	```
  	 $ sudo installer -pkg graphviz-2.34.0.pkg -target /
  	```


3. ### wxPython libraries ###

  The GUI user interface uses the wxPython libraries.

	http://www.wxpython.org/download.php

  There are many different wxPython packages. You should choose a 32-bit
  package that matches your Python version (e.g., 2.7). It is
  recommended to select the unicode version from the stable releases.

  As of writing (May 2013) the following links lead to the appropriate
  wxPython packages for Python 2.7:

  *	**Windows**
  
   	http://downloads.sourceforge.net/wxpython/wxPython2.8-win32-unicode-2.8.12.1-py27.exe

  *	**Mac OS X**
  
   	http://downloads.sourceforge.net/wxpython/wxPython2.8-osx-unicode-2.8.12.1-universal-py2.7.dmg

   	Note that this package is in an old format and you will probably
   	get a warning "Package is damaged". This can be resolved by:
   	
   	```
   	 $ sudo installer -pkg /Volume/.../wxPython2.8-osx-unicode-universal-py2.7.pkg/ -target /
   	```

  *	**Ubuntu/Debian Linux**
  
   	http://wiki.wxpython.org/InstallingOnUbuntuOrDebian


Running Scyther
---------------

Extract the Scyther archive and navigate to the extracted directory.

Start Scyther by executing the file

  	scyther-gui.py

in the main directory of the extracted archive.

  *	**Mac OS X**
  
  	Right-click the file 'scyther-gui.py' and select "Open with" and
  	then "Python Launcher".


