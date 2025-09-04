Ubuntu 24.04.1 ([scyther/README.md at master · cascremers/scyther](https://github.com/cascremers/scyther/blob/master/README.md))

1. Open the terminal and run the following command to download the dependencies
   
    `sudo apt install cmake build-essential flex bison gcc-multilib python3-minimal`

2. Install git using the following command
   
    `sudo apt install git`

3. Move to the directory where you want to clone scyther into. I’ve chosen ‘Desktop’, and cloned scyther there

    `cd Desktop`

    `git clone https://github.com/cascremers/scyther.git`

4. After the cloning is complete, move to the scyther directory

    `cd scyther`

5. Run the following command to build the files in the `Desktop/scyther` directory,

   `./build.sh`

6. We install graphviz using,

   `“sudo apt install graphviz`

7. After scyther has been built successfully, we move to the gui folder `cd../gui` and run the following command to run scyther,
 
     `python3 scyther-gui.py`
8. To check the verification of protocols from the terminal itself, use the command,

    `./scyther-linux -A [protocol file name.spdl]` the protocol file name is to be replaced by the file to be checked, for example ns3.spdl

9. Can also use the following command for more information

     `./scyther-linux –help` or `./scyther-linux –long-help`

For more , check [the general overview](https://cispa.saarland/group/cremers/scyther/install-generic.html)
