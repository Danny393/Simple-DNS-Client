#import socket module to be able to create network sockets
from socket import socket, AF_INET, SOCK_DGRAM;
import sys;

#establish basic client side socket (UDP)
clientSocket = socket(AF_INET, SOCK_DGRAM)

#command line inputs that need to be check 
domainName = sys.argv[1]
serverIP = sys.argv[2]
serverPort = 53

#send dns message to root dns server
clientSocket.sendto(bytes("QUERY " + domainName + "\r\n", 'ascii'),(serverIP, serverPort))

#timeout to ensure that the socket is not wiating forever for response
clientSocket.settimeout(5)
data = clientSocket.recv(1024)
print(str(data))