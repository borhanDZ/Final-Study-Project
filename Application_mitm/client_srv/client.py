import argparse
import socket
import sys


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t",dest="target",help="Target's IP. If not specified")
    parser.add_argument("-p", dest="port", help="Spesific the port Number where you want to listen",type=int)
    return parser.parse_args()

def client(HOST,PORT):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

          client.connect((HOST,PORT))
          buffer = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % HOST
          print buffer
          if len(buffer):
              client.send(buffer)
          while True:
              # now wait for data back
               recv_len = 1
               response = ''

               while recv_len :

                   data = client.recv(4096)
                   recv_len  = len(data)
                   response += data

                   if recv_len < 4096:
                              break
               print response
               if response == "kill":
                  print "Connection Finshed"
                  client.close()
                  break
             # wait for more input
               buffer = raw_input("")
               buffer += "\n"

        # send it off
               client.send(buffer)

    except :
          print "[*] Exception! Exiting."
        # tear down the connection
          client.close()


#client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client.connect((HOST, PORT))
def main():

    args = argument()
    HOST = args.target
    PORT = args.port
    print HOST,PORT
    client(HOST,PORT)
if __name__ == '__main__':

     main()

