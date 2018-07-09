# portScanner

portScanner is a tool for scanning whole network or any number of hosts in a network to find open ports and vulnerable services running on the machine.

For example : the network format can be 192.168.31.0/24 (whole network), 192.168.31.10-25(some hosts in the network), or a single host like 192.168.31.5 or 192.168.31.5/32

[![asciicast](https://asciinema.org/a/3fWX1ufPwYUhfWdJIfeiECkro.png)](https://asciinema.org/a/3fWX1ufPwYUhfWdJIfeiECkro)

# Modules
  * **http** - Scans for open ports Http Ports eg. 80,443,8080,8081,9090,9091
  * **mongodb** - Scans for MongoDb instances. eg: 27017
  * **mysql** - Scans for mysql instances. eg: 3306,3307
  * **ssh** - Scans for SSH eg: 22,22222
  * **printer** - Scans for printer ports eg: 515,9100
  * **fullscan** - Scans for all ports.

# Commands
  * **MODULES** - List all modules - 'modules'
  * **USE** - Use a module - 'use module_name'
  * **OPTIONS** - Show a module's options - 'options'
  * **SET** - Set an option - 'set option_name option_value'
  * **RUN** - Run the selected module - 'run'
  * **FULL SCAN** - Scan the whole network - 'fullscan'
  * **BACK** - Go back to menu - 'back'
  * **EXIT** - Shut down portScanner - 'exit'

# Installing
## Linux(Debian)
```
  $ sudo apt-get update && sudo apt-get install python3 python3-pip -y  

  $ git clone https://github.com/tinyb0y/portScanner.git

  $ cd portScanner/

  $ python3 -m pip install -r requirements.txt
```
# Usage:
  ### Settings in app.cfg

  ```
  options = -sV
  cores=8
  ```

  You may add more options like -O for OS Detection (Scan time may take a little longer for matching the nmap signatures)

  ### Start portScanner with python3:
  ```
  > python3 portScanner.py

  ```

  ### Select a Module: (eg: http)

  ```
    tinyb0y $> use http
    tinyb0y/http $>
  ```

  ### View the module Options:
  ```
    tinyb0y/http $> options

    Options for module 'http':
    verbose - Show verbose output  ==> 'true'
    network - IP range to scan ==> [NOT SET]
    port - Port to Scan  ==> '80,443,8080'
    filename - Set filename Full path ==> [NOT SET]
  ```

   ### Set the network or filename:

  ```
   tinyb0y/http $> set network 192.168.31.5
  ```
   * Filename provided should be absolute path for running smoothly
  ```
    tinyb0y/http $> run
    Logs are saved in logs/ directory
  ```

  ### Running portScanner with Command Line Arguments
  ```
    > python3 portScanner.py -h
    usage: portScanner.py [-h] [--interactive INTERACTIVE] [--module MODULE]
                          [--network NETWORK] [--port PORT] [--verbose VERBOSE]
                          [--filename FILENAME] [--bruteforce BRUTEFORCE] [--test]

    portScanner

    optional arguments:
      -h, --help            show this help message and exit
      --interactive INTERACTIVE, -i INTERACTIVE
                            1 for Interactive Mode, 0 for Commandline (default: 1)
      --module MODULE, -m MODULE
                            Module name to scan -> http telnet mysql ssh ftp
                            printer fullscan (default: fullscan)
      --network NETWORK, -n NETWORK
                            Network to scan (default: None)
      --port PORT, -p PORT  Port to scan (default: None)
      --verbose VERBOSE, -v VERBOSE
                            Verbose Level (default: True)
      --filename FILENAME, -f FILENAME
                            Absolute Path of the filename (default: True)
      --bruteforce BRUTEFORCE, -b BRUTEFORCE
                            Brute Attack (default: False)
      --test
  ```
  ```
  > python3 portScanner.py -i 0 -m fullscan -n 192.168.31.5
  ```
  -i 0 for commandline mode

  ### Starting the web server
  ```
    > python3 app.py
  ```

  # Disclaimer:
  I'm not responsible for anything you do with this program, so please only use it for good and educational purposes.

 If any suggestions, mail me at **tinyb0y{at}protonmail{dot}com**
