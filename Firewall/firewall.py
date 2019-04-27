from scapy.all import *
from netfilterqueue import NetfilterQueue
import logging
import re
import time
non_acceptable="192.168.43.79" # IP to be blocked
packets_from_each_ip=dict() # to store the packets from each ip that is allowed to send.





def rules(packet):
	pkt=IP(packet.get_payload())
	print(pkt.src)
	print(pkt.dst)
	source=str(pkt.dst)
	print(source,non_acceptable)
	if(source==non_acceptable):
		packet.drop() # For now it is a string match. which can go for regex match or any kind of set match too.
		print('You are not authorized to send data/request to this destination!!')# print statement to be displayed 
	else:
		print('allowed')#allowed packet. unblocked
		packet.accept()
		if(pkt.src not in packets_from_each_ip):
			packets_from_each_ip[pkt.src]=[]
		#print(type(pkt))
		packets_from_each_ip[pkt.src].append(pkt) # adding the latest packet into the dictionary
		if(len(packets_from_each_ip[pkt.src])>10):
			print('Deleting a history as buffer size reached maximum size.!!')# deleting an older packet
			packets_from_each_ip[pkt.src]=packets_from_each_ip[pkt.src][-10:]



def set_ip_forwarding(value):
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
        file.write(str(value)) #setting the ip address forwarding to 1
        file.close()







class iptables:

	dns     = False
	http    = False
	smb     = False
	nfqueue = False

	__shared_state = {}

	def __init__(self):
		self.__dict__ = self.__shared_state

	def flush(self):
		os.system('iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0') # redirecting to nfqueue number 0
		self.dns  = False
		self.http = False
		self.smb  = False
		self.nfqueue = False
	def NFQUEUE(self):
		os.system('iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0') # removing ip table entry
		self.nfqueue = True

set_ip_forwarding(1)
iptables().NFQUEUE()
nfqueue = NetfilterQueue()
nfqueue.bind(0,rules)
print('done')
try:
    nfqueue.run()
except KeyboardInterrupt:
	for i in packets_from_each_ip:
		print('Number of packets received from ',i,':',len(packets_from_each_ip[i]))
	print('The server is temporarily down!!. Please wait for a while for it to come back!!')

nfqueue.unbind()
set_ip_forwarding(0)
iptables().flush()

'''
To run this firewall script, make sure you have all the packages preinstalled. 
Run the script in sudo or super user mode.
Test it using ping command from the source to the destination and change the ip address you want to block to test everything.
sudo python3 firewall.py
'''
