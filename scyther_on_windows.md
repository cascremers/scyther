1. Install [MSYS2](https://www.msys2.org) and run it.

2. Run the following command to install some tools for compilation:
 `$ pacman -S mingw-w64-ucrt-x86_64-gcc`

3. [from the msys2 terminal] Install the MingW cross compiler using the following command:
 `pacman -S mingw-w64-cross-toolchain make cmake`
 
   Note, when prompted to `Enter a selection(default = all):` just press enter to download everything.

4. Install git using the command
`pacman -S git`

5. Clone the repository
 `git clone https://github.com/cascremers/scyther.git`

6. Download the dependencies
 `pacman -S python3 flex bison`

7. Run the build using the following command:
 `./subbuild-unix-w32.sh` ,
 you might face an error in this step like `./subbuild-unix-w32.sh: No such file or directory`
 To fix this error, move into the `/src/build` directory and then run the command from there,

   The execution might still lead to an error, stating that "scyther-w32.exe" doesn't exist
   This is fixed by running this simple command:
   `mv scyther-w32.exe.exe scyther-w32.exe`, and then running the build command again.

8. Move to the directory `/scyther/src`, here the output of after running the build command is as follows:
 
   ```$ ./subbuild-unix-w32.sh
 
   -- Found Flex: /usr/bin/flex.exe

   -- Found Bison: /usr/bin/bison.exe

   -- Locating platform specific file BuildUnix-Win32.cmake

   -- Building W32 version

   -- Configuring done (0.6s)

   -- Generating done (0.6s)

   -- Build files have been written to: /home/machine_name/scyther/src

   [100%] Built target scyther-w32.exe


   "---------------------------------------------------------

   Built the Windows binary
 
   Copied the file to the gui/Scyther directory

    ---------------------------------------------------------"

9. We stay in the same directory and type `ls`, and we look for the file named “scyther-w32.exe”.

10. We run the following command to test whether scyther works:
    `./scyther-w32.exe`,
   If we get an output like so,

  ```Try 'scyther --help' for more information, or visit:
  
  https://cispa.saarland/group/cremers/scyther/index.html
```
then scyther works as expected.


11. To check the security protocol analysis, we can run the following command:

   `./scyther-w32.exe -A ns3.spdl`, where ns3.spdl can be replaced by any other protocol file to be tested.

for more information, check [building scyther on windows](https://github.com/cascremers/scyther/wiki/Instructions-for-building-on-Windows).

Also check [this link](https://people.cispa.io/cas.cremers/scyther/install-generic.html) , to get an idea of the generic installation.





