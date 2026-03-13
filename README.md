# Basic Attack Automation Script
This script will automate the process of discovering weak usernames and passwords that may exist on a common group of services that may be running on a host. 

The script will input and subsequently read a file containing IP addresses, and for each IP address in the list the script will scan the chosen ports on that host. The script will then attempt to bruteforce a certain subset of selected services if they are running on the host.

These services are Telnet, SSH and basic web servers that may be found running on port 80, 8080 or 8888.
