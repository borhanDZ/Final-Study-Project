# !/usr/bin/env python
"""
srv_controle as you also call sever control this a short program allow you to controle your
application on system linux remotelly by a simple command to put it your shell command
"""
import socket
import threading
import argparse
import subprocess


def run_command(command):
    # trim the newline
    command = command.rstrip()

    # run the command and get the output back
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "[!]Failed to execute command.\r\n"
        # send the output back to the client
    return output


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", dest="command", help="execute a command ex '/etc/passwd' ")
    parser.add_argument("-l", help="Listen connections from any IP")
    parser.add_argument("-p", dest="port", help="Spesific the port Number where you want to listen", type=int)
    return parser.parse_args()


# this Function dump shell command line '/bin/bash'
def shell(execute, c):
    if execute == '/bin/bash':
        c.send("shell:~$")
        # run the command
        print "*************"
        while True:
            req_com = c.recv(1024)
            print req_com.split(), "+++++++++++++"
            if req_com == "dump\n":
                print "kill shell"
                break
            output = run_command(req_com)
            output = "shell:~$" + output
            c.send(output)
    else:
        print "specific teh shell name ex: -c '/bin/bash' "


def server(bind_host, bind_port, execute):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print type(bind_port)
    server.bind((bind_host, bind_port))
    server.listen(5)
    print "[*] Listening on %s:%d" % (bind_host, bind_port)

    # this is our client-handling thread
    def handle_client(client_socket):
        try:

            while True:  # print out what the client sends
                print "!!!!!!!!!!!!!!!!!"
                request = client_socket.recv(1024)
                print "[*] Received: %s" % request
                if request == "shell\n":
                    shell(execute, client_socket)
                # send back a packet
                if request == "exit\n":
                    client_socket.send("The connections was be Finshed")
                    client_socket.send("kill")
                    client_socket.close()
                    break
                client_socket.send("ACK!")

        except:
            print "[*]connection Failed"
            client_socket.close()

    while True:
        client, addr = server.accept()
        print "[*] Accepted connection from: %s:%d" % (addr[0], addr[1])

        # spin up our client thread to handle incoming data
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()


def main():

    args = argument()
    if  args:
     print "yes"
     host = "192.168.1.116"
     port = 4444 #args.port
     com = args.command
     print com,"***",type(com)
     #server(host, port, com)


if __name__ == '__main__':
    main()
