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
4.     docker run --rm <name>:<version> <cli arguments>
       example: docker run --rm myoscap --scan

## Command Line Arguments
    -h --help            Show help message and exit
    --scan               Start a new scan
    --history            List past scans
    --scan-id <id>       Show results of scan with a certain id
    --compare <id> <id>  Compare 2 scans by id

## Usage
    docker run --rm myoscap -h               //Shows help message
    docker run --rm myoscap --scan           //Starts a new scan
    docker run --rm myoscap --scan-id 1      //Shows result of scan with id 1
    docker run --rm myoscap --history        //Display scan history
    docker run --rm myoscap --compare 1 2    //Compares scan with id 1 against scan with id 2

## Testing
To facilitate testing, the docker image already contains 2 scans with diferences in order to test compare, history and scan-id functionality

