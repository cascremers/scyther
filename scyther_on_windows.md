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

7. Move to the directory `/scyther/src`, and run the command `make`. You'll get an output like,
 
   ```
     [100%] Built target scyther-w32.exe
   ```

8. We stay in the same directory and type `ls`, and we look for the file named “scyther-w32.exe”.

9. We run the following command to test whether scyther works:
    `./scyther-w32.exe`,
   If we get an output like so,

  ```
  Try 'scyther --help' for more information, or visit:
  
  https://cispa.saarland/group/cremers/scyther/index.html
```
then scyther works as expected.


10. To check the security protocol analysis, we can run the following command:

   `./scyther-w32.exe -A ns3.spdl`, where ns3.spdl can be replaced by any other protocol file to be tested.

for more information, check [building scyther on windows](https://github.com/cascremers/scyther/wiki/Instructions-for-building-on-Windows).

Also check [the general overview](https://people.cispa.io/cas.cremers/scyther/install-generic.html), to get an idea of the generic installation.





