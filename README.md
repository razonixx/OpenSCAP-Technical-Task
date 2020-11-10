# Oracle interview: technical task

This is a python command line tool to run OpenSCAP scans for Oracle Linux 7.<br>
The scan is ran using the "stig" profile provided by the scap-security-guide package.

## Requirements
Docker

## Installation 
1.     docker pull oraclelinux:7
2.     cd into repo
3.     docker build --tag <name>:<version> .
       example: docker build --tag myoscap:latest .
4.     docker run -it -d <name>:<version>
       example: docker run -it -d myoscap
5.     docker start -i <container ID>
## Command Line Arguments
    -h --help            Show help message and exit
    --scan               Start a new scan
    --history            List past scans
    --scan-id <id>       Show results of scan with a certain id
    --compare <id> <id>  Compare 2 scans by id

## Usage
    python3 my_oscap.py -h               //Shows help message
    python3 my_oscap.py --scan           //Starts a new scan
    python3 my_oscap.py --scan-id 1      //Shows result of scan with id 1
    python3 my_oscap.py --history        //Display scan history
    python3 my_oscap.py --compare 1 2    //Compares scan with id 1 against scan with id 2

## Testing
To facilitate testing, the docker image already contains 2 scans with diferences in order to test compare functionality

