# capture ARP packet in windowsfrom ctypes import *
from winpcapy import *
import time
import sys
import string
import socket

#
# Basic structures and data definitions for AF_INET family
#
class S_un_b(Structure):
    _fields_ = [("s_b1",c_ubyte),
                ("s_b2",c_ubyte),
                ("s_b3",c_ubyte),
                ("s_b4",c_ubyte)]

class S_un_w(Structure):
    _fields_ = [("s_wl",c_ushort),
                ("s_w2",c_ushort)]

class S_un(Union):
    _fields_ = [("S_un_b",S_un_b),
                ("S_un_w",S_un_w),
                ("S_addr",c_ulong)]

class in_addr(Structure):
    _fields_ = [("S_un",S_un)]


class sockaddr_in(Structure):
    _fields_ = [("sin_family", c_ushort),
                ("sin_port", c_ushort),
                ("sin_addr", in_addr),
                ("sin_zero", c_char * 8)]


class ARP:
	def __init__(self):
		# the public network interface
		# socket.gethostname()='TPE-DCHUNG'
		# socket.gethostbyname(socket.gethostname())='10.162.224.158'
		self.IP = socket.gethostbyname(socket.gethostname())
		self.LINE_LEN = 16

	def iptos(self, in_):
	   return "%d.%d.%d.%d" % (in_.s_b1, in_.s_b2, in_.s_b3, in_.s_b4)

	def ifprint(self, d):
	    a = POINTER(pcap_addr_t)

	    ## Name
	    #print("%s\n" % d.name)
	    ## Description
	    #if (d.description):
	    #    print ("\tDescription: %s\n" % d.description)

	    ## IP addresses
	    if d.addresses:
	        a = d.addresses.contents
	    else:
	        a = False
	    while a:
	        if a.addr.contents.sa_family == socket.AF_INET:
	            mysockaddr_in = sockaddr_in
	            if (a.addr):
	                aTmp = cast(a.addr,POINTER(mysockaddr_in))
	                #print ("\tAddress: %s\n" % self.iptos(aTmp.contents.sin_addr.S_un.S_un_b))
	                return self.iptos(aTmp.contents.sin_addr.S_un.S_un_b)
	        if a.next:
	            a = a.next.contents
	        else:
	            a = False

	def capture(self, recv_num):
		alldevs = POINTER(pcap_if_t)()
		d = POINTER(pcap_if_t)
		errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
		header = POINTER(pcap_pkthdr)()
		pkt_data = POINTER(c_ubyte)()

		## Retrieve the device list
		if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
		    print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
		    return False

		d = alldevs.contents

		while d:
		    get_ip_address = self.ifprint(d)

		    # select the ethernet card by IP address
		    if get_ip_address == self.IP:
		    	break

		    if d.next:
		         d = d.next.contents
		    else:
		         d = False

		print "get current interface >>>>>>>>>\n"
		print("%s\n" % d.name)
		print ("\tDescription: %s\n" % d.description)

		adhandle = pcap_open_live(d.name, 65536, 1, 1000, errbuf)
		if (adhandle == None):
			#print("\nUnable to open the adapter. %s is not supported by Pcap-WinPcap\n" % d.contents.name)
			## Free the device list
			pcap_freealldevs(alldevs)
			return False

		#print("\nlistening on %s...\n" % (d.description))
		## At this point, we don't need any more the device list. Free it
		pcap_freealldevs(alldevs)

		## Read the packets
		res = pcap_next_ex( adhandle, byref(header), byref(pkt_data))

		arp_list = []
		arp_type = "0x0806"

		recv_pkt_num = 1
		while(res >= 0):
			if recv_pkt_num > recv_num:
				break
			arp_dict = {}
			if(res == 0):
				## Timeout elapsed
				break
			## print pkt timestamp and pkt len
			print ("%ld:%ld (%ld)\n" % (header.contents.ts.tv_sec,header.contents.ts.tv_usec, header.contents.len))
			##  Print the packet
			print "Recv #%d >>>>>>>>\n" %recv_pkt_num
			packet = []
			for i in range(1,header.contents.len + 1):
				packet.append("%.2x" % pkt_data[i-1])

			print ("\n")
			eth_type = "0x" + packet[12] + packet[13]
			print "eth_type = %s" %eth_type
			if eth_type != arp_type:
				print "not ARP"
			else:
				print "ARP"
				print packet
				arp_dict['eth_type'] = eth_type
				eth_destination = ":".join(packet[i] for i in xrange(0, 6))
				print "eth_destination = %s" %eth_destination
				arp_dict['eth_destination'] = eth_destination
				eth_source = ":".join(packet[i] for i in xrange(6, 12))
				arp_dict['eth_source'] = eth_source
				arp_sender_mac = ":".join(packet[i] for i in xrange(22, 28))
				arp_dict['arp_sender_mac'] = arp_sender_mac

				arp_sender_ip=""
				for i in xrange(28, 32):
					arp_sender_ip += str(int(packet[i], 16)) + "."
				arp_sender_ip = arp_sender_ip.rstrip(".")

				print "arp_sender_ip = %s" %arp_sender_ip
				arp_dict['arp_sender_ip'] = arp_sender_ip
				arp_target_mac = ":".join(packet[i] for i in xrange(32, 38))
				arp_dict['arp_target_mac'] = arp_target_mac

				arp_target_ip=""
				for i in xrange(38, 42):
					arp_target_ip += str(int(packet[i], 16)) + "."
				arp_target_ip = arp_target_ip.rstrip(".")
				arp_dict['arp_target_ip'] = arp_target_ip

				arp_list.append(arp_dict)

			res = pcap_next_ex(adhandle, byref(header), byref(pkt_data))
			recv_pkt_num += 1

		if(res == -1):
		    print ("Error reading the packets: %s\n" % pcap_geterr(adhandle))
		    return False

		print "arp_list = %s" %arp_list
		print "collect %d ARP packet" %len(arp_list)

	def close(self):
		pcap_close(adhandle)
		return True

if __name__ == '__main__':
	myarp = ARP()
	myarp.capture(5)