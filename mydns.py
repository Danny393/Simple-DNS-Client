#import socket module to be able to create network sockets
from socket import socket, AF_INET, SOCK_DGRAM
import sys
import struct

#establish basic client side socket (UDP)
clientSocket = socket(AF_INET, SOCK_DGRAM)

#command line inputs that need to be check 
domainName = sys.argv[1]
serverIP = sys.argv[2]
serverPort = 53

#Header
#ID 16 bit identifier for mathcing queries to replies //1337 or some constant
#QR 1 bit field for request or response, 0 is for request, 1 is for response
#OPCODE 4 bit field that specifies the kind of query, 0 is for standard query
#AA 1 bit field that specifies if the response is from an authoritative server
#TC 1 bit truncation
#RD 1 bit that states if the query should be answered recursively (0 since we want iterative)
#RA 1 bit if recursion is supported on the server
#Z  3 bit for future use (most likely 0)
#RCODE 4 bitfor response code, values from 0-5
#QDCOUNT 16 bit int for number of questions (1 when query)
#ANCOUNT 16 bit int for number of answers (0 answers when query)
#NSCOUNT 16 bit int for number of resource records in authority section
#ARCOUNT 16 bit int for number of resource records in additional section

#Data

packet = struct.pack("H", 3939) #ID
packet += struct.pack("B", 1) #QR OPCODE AA TC RD
packet += struct.pack("B", 0) #RA Z RCODE
packet += struct.pack("!H", 1) #QDCOUNT
packet += struct.pack("H", 0) #ANCOUNT
packet += struct.pack("H", 0) #NSCOUNT
packet += struct.pack("H", 0) #ARCOUNT

#data
domain="leetcode"
packet += struct.pack("B", len(domain))
for byte in bytes(domain,'ascii'):
 packet += struct.pack("B", byte)

domain="com"
packet += struct.pack("B", len(domain))
for byte in bytes(domain,'ascii'):
 packet += struct.pack("B", byte)

packet += struct.pack("B", 0) #End of string

packet += struct.pack("!H", 1) #QTYPE
packet += struct.pack("!H", 1) #QCLASS

#timeout to ensure that the socket is not wiating forever for response
#send dns message to root dns server
clientSocket.sendto(bytes(packet),(serverIP, serverPort))

print("Waiting for response...")
clientSocket.settimeout(5)
data = clientSocket.recv(1024)
print(str(data))
clientSocket.close()