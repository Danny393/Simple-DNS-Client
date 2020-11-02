#import socket module to be able to create network sockets
from socket import socket, AF_INET, SOCK_DGRAM
import sys
import struct

#function definitions

#this function builds the DNS query message that will be used for lookup
def buildQuery(queryAddress):

  #Header
  #ID 16 bit identifier for mathcing queries to replies //1337 or some constant
  #QR 1 bit field for request or response, 0 is for request, 1 is for response
  #OPCODE 4 bit field that specifies the kind of query, 0 is for standard query
  #AA 1 bit field that specifies if the response is from an authoritative server
  #TC 1 bit truncation
  #RD 1 bit that states if the query should be answered recursively
  #RA 1 bit if recursion is supported on the server
  #Z  3 bit for future use 
  #RCODE 4 bitfor response code, values from 0-5
  #QDCOUNT 16 bit int for number of questions (1 when query)
  #ANCOUNT 16 bit int for number of answers (0 answers when query)
  #NSCOUNT 16 bit int for number of resource records in authority section
  #ARCOUNT 16 bit int for number of resource records in additional section

  packet = struct.pack("H", 3939) #ID
  packet += struct.pack("B", 1) #QR OPCODE AA TC RD
  packet += struct.pack("B", 0) #RA Z RCODE
  packet += struct.pack("!H", 1) #QDCOUNT
  packet += struct.pack("H", 0) #ANCOUNT
  packet += struct.pack("H", 0) #NSCOUNT
  packet += struct.pack("H", 0) #ARCOUNT

  #Data (Fill this in really quick)

  values = queryAddress.split(".")

  for domain in values:
    packet += struct.pack("B", len(domain))

    for byte in bytes(domain,'ascii'):
      packet += struct.pack("B", byte)

  packet += struct.pack("B", 0) #End of string

  packet += struct.pack("!H", 1) #QTYPE
  packet += struct.pack("!H", 1) #QCLASS

  return packet

############################################################# 

def readName(data, pos):

  name = "" #string to hold domain name

  #main loop that will read chars if question field states there are more values
  while(int(str(struct.unpack("B",data[pos:pos + 1]))[1:-2]) != 0):
    #we know the number is not 0 so we can try to read val# of chars
    val = int(str(struct.unpack("B",data[pos:pos + 1]))[1:-2])

    #if we see the pointer value then use pointer to get the rest of the name and then push pos to next bit
    if(val == 192):
      pos += 1
      pointer = int(str(struct.unpack("B",data[pos:pos + 1]))[1:-2])
      name += readName(data,pointer)[1]
      pos += 1

      return (pos,name)

    pos += 1 #we have to move pos so that it is accurate and start at the next char

    #loop through all bytes that are part of the name
    for i in range(val):
      #read the char interpretation of they byte
      name += str(struct.unpack("c",data[pos + i:pos + i + 1]))[3:-3]

    #after the field is read we add a dot after and push pos by the number of chars read
    name+="."
    pos+= val

  #push pos by 1 to get past the 0 seen
  pos += 1
  #we can return both the position and the String back at the same time, also removing the extra .
  return (pos,name[:-1])

############################################################# 

#large loop may start here where domain name is set, this would be a function, and we can call it
#recursively, until it finds an answer, and then it would return true and the other recursive functions would end as well
#or we could just exit but that does not sound elegant
def dnslookup(serverIP):
  #if we saw any answers then we can return true, this loop may never actually go through more than
  #one dfs path deep anyways but it is a safety mesaure
  #if no path is found then all servers and their info are listed, while massive, it will be accurate

  print("-----------------------------------------------")
  print("DNS server to query:",serverIP)

  #send dns message to root dns server
  try:
    clientSocket.sendto(bytes(query),(serverIP, serverPort))
    data = clientSocket.recv(2048)
  except Exception:
    print("DNS address was not valid")
    sys.exit()

  print("Reply Recieved. Content Overview:")

  pos = 0
  pos += 2 # read ID
  pos += 1 # read some flags
  pos += 1 # read more flags
  nq = int(str(struct.unpack("!H", data[4:6]))[1:-2])
  pos += 2 # read number of questions
  na = int(str(struct.unpack("!H", data[6:8]))[1:-2])
  print("  ",na, "Answers")
  pos += 2
  ni = int(str(struct.unpack("!H", data[8:10]))[1:-2])
  print("  ",ni,"Intermediate Name Servers")
  pos += 2
  nar = int(str(struct.unpack("!H", data[10:12]))[1:-2])
  print("  ",nar,"Additional Information Records")
  pos += 2

  #Even though we do not print the question section we still need to get past it
  #print("Query Section:")
  for i in range(nq):
    (p,name) = readName(data,pos) #read name
    pos = p
    pos += 2 #read type
    pos += 2 #read class

  print("Answers Section:")
  for i in range(na):
    (p1,name1) = readName(data,pos)
    pos = p1
    pos += 2 #read type
    pos += 2 #read type
    pos += 4 #read time to live
    pos += 2 #read data length
    #grab the IP for this field
    ip = str(struct.unpack("B", data[pos:pos+1]))[1:-2] + "."
    pos += 1
    ip += str(struct.unpack("B", data[pos:pos+1]))[1:-2] + "."
    pos += 1
    ip += str(struct.unpack("B", data[pos:pos+1]))[1:-2] + "."
    pos += 1
    ip += str(struct.unpack("B", data[pos:pos+1]))[1:-2]
    pos += 1

    print("     Name:",name1,"    IP:",ip)


  print("Authoritative Section:")
  for i in range(ni):
    (p1,name1) = readName(data,pos) #read name
    pos = p1
    pos += 2 #read type
    pos += 2 #read class
    pos += 4 #read time to live
    pos += 2 #read data length
    (p2,name2) = readName(data,pos) #read data
    pos = p2

    print("     Name:",name1,"    NameServer:",name2)

  listIP = []
  print("Additional Information Section")
  for i in range (nar):
    (p1,name1) = readName(data,pos)
    pos = p1
    typeIP = str(struct.unpack("!H",data[pos:pos+2]))[1:-2]
    pos += 2 #read type
    pos += 2 #read class
    pos += 4 #read time to live
    pos += 2 #read data length

    #only process IPv4
    if(typeIP=="1"):
      #grab the IP for this field
      ip = str(struct.unpack("B", data[pos:pos+1]))[1:-2] + "."
      pos += 1
      ip += str(struct.unpack("B", data[pos:pos+1]))[1:-2] + "."
      pos += 1
      ip += str(struct.unpack("B", data[pos:pos+1]))[1:-2] + "."
      pos += 1
      ip += str(struct.unpack("B", data[pos:pos+1]))[1:-2]
      pos += 1

      print("     Name: %-23s IP: %s"% (name1,ip))
      #print("     Name:",name1,"    IP:",ip)
      listIP.append(ip)

    else:
      #get pass the 16 byte IPv6 address field
      pos += 16
      print("     Name: "+name1)
  
  #if we see an answer then we can quit gracefully
  if(na > 0): 
    print("\nIP address for",domainName,"found")
    return True

  #otherwise we need to go through all the IP's we collected and search with recursion
  for ip in listIP:
    input("\nPress Enter to continue searching with IP: "+ip+"\n")
    if(dnslookup(ip) == True):
      return True

  return False

############################################################# 

#establish basic client side socket (UDP)
clientSocket = socket(AF_INET, SOCK_DGRAM)

#basic user input check
if(len(sys.argv) != 3):
  print("Please only enter a domain name to query and then a root DNS IP address")
  sys.exit()

domainName = sys.argv[1]
sDNS_IP = sys.argv[2]
serverPort = 53

#lets do a checek on the IP address
#make sure it is only made up of . and digits
for values in sDNS_IP:
  if(not values.isdigit() and values != "."):
    print("Please enter an IP address for your second input")
    sys.exit()

#timeout to ensure that the socket is not wiating forever for response
clientSocket.settimeout(2)

#building of the DNS query message that we will use for all queries
query = buildQuery(domainName)

#start of recursive query
#this is a recursive stragety but an iterative DNS lookup since
#our computer is recieving and sending all info and not passing 
#the task of searching and requesting to a DNS server
dnslookup(sDNS_IP)

#close the socket to return resources back to CPU
clientSocket.close()
