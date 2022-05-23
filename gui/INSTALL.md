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

  Scyther requires **Python 3** now, and no longer supports Python 2. 

  *	**Mac OS X**
  
  	If the package yields an error when you try to install it,
  	please use the following, in the directory where you downloaded
  	it:
  	
  	```
  	 $ sudo installer -pkg graphviz-2.34.0.pkg -target /
  	```


3. ### wxPython libraries ###

  The GUI user interface uses the wxPython libraries.
  The recommended way of installing is through `pip` and described this page:

	https://www.wxpython.org/download.php

  This version of Scyther requires at least **wxPython 4.0**. Note that older versions of Scyther did not work with wxPython 4.

  For Ubuntu users, it is important to add an additional parameter, e.g., for Ubuntu 20.04, the recommended pip install is:

  ```
   $ sudo apt install python-pip
   $ pip install -U \
    -f https://extras.wxpython.org/wxPython4/extras/linux/gtk3/ubuntu-20.04 \
    wxPython
  ```

Running Scyther
---------------

Extract the Scyther archive and navigate to the extracted directory.

Start Scyther by executing the file

  	`scyther-gui.py`

in the main directory of the extracted archive.

  *	**Mac OS X**
  
  	Right-click the file `scyther-gui.py` and select "Open with" and
  	then "Python Launcher".


