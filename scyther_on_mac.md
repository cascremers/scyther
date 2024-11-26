1. Open the Terminal
2. Install [Homebrew](https://brew.sh/), the  macOS package manager, by running the following command:
   
    “/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)””

3. Add it to the PATH by using the following commands,

    “echo >> ~/.zprofile”,

    “echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile”,

    “eval "$(/opt/homebrew/bin/brew shellenv)””

    You can also find these steps when the installation of Homebrew is completed, under the “Next Steps”

4. To check if Homebrew is working as intended or not, we can run the following command,

    “brew help”, which should display the example usage of brew.

5. Move to Desktop and clone scyther,

   “cd Desktop”

    “git clone https://github.com/cascremers/scyther.git”

6. Move to the scyther folder, “cd scyther”

7. Run the following command to check the tag,
    “git tag”, and make sure that there exists a v1.2 

8. Go the ‘gui’ folder, and run the following command to install wxPython,
    “python3 scyther-gui.py”, this will automatically install wxPython on the machine.

9. To install graphviz, install it by,

    “brew install graphviz”

10. Move to the src directory, and run the following command to build scyther on the machine,

    “cmake -G "Unix Makefiles" ”

11. Type in “make” to compile the files.

12. The following command, will give us an overview of how to use scyther through the terminal,

    “./scyther-mac --help”

13. Use the following command to run a protocol and check its security claims,

    “./scyther-mac -A [filename].spdl”, replace filename with the one that you want to check for.
