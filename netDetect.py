import sys
import dpkt
from scapy.all import *
#this is a network trace application for checking for port scanning
#it checks to see if the packet uses Ethernet, IP, and TCP and ignores malformed
#packets
#mostly used dpkt but used (shitty)scapy for some socket stuff
#http://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html
#found above website to be helpful, used examples from this to help construct mine
syn = [] # holds all syns
singSyn = [] #holds single ip
ack = [] #holds all syn + ack


for ts, buf in dpkt.pcap.Reader(open(sys.argv[1])):
    #if cant pass ignore
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except: continue

    if type(eth.data) != dpkt.ip.IP: continue
    ip = eth.data

    if type(ip.data) != dpkt.tcp.TCP: continue
    tcp = ip.data
    #getting rid of all nasty things(IP'S that may not conform to whats wanted)
    syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
    ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
    #setting flags

    if (inet_ntoa(ip.src) not in singSyn):  #populating first array of single IP
        singSyn.append(inet_ntoa(ip.src))
    if syn_flag == True and ack_flag == False:  #check flags and populate if src
        syn.append(inet_ntoa(ip.src))           #conditions met
    elif syn_flag == True and ack_flag == True: #populate array if dst conditions
        ack.append(inet_ntoa(ip.dst))           #are met

#test = []
for x in singSyn:   #loop through single IP array
    count1 = 0  #counts for sny vs ack
    count2 = 0
    for i in syn:   #check syns
        if (i == x):
            count1+=1
    for j in ack:   #check acks + syns
        if (j == x):
            count2+=1
    try:
        if (count1) > (3*count2): #seeing more dst requests
            print x #prints overscanning
            #test.append(x)#just test stuff
    except:
        continue

#for y in test:
#    if y == "128.3.23.2" or y == "128.3.23.5" or y == "128.3.23.117" or y == "128.3.23.158" or y == "128.3.164.248" or y == "128.3.164.249":
#        print "yes ", y
