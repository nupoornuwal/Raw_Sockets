#!/usr/bin/python
import socket, IN
import random
from struct import *
import time
import subprocess
import sys 
import os
from urlparse import urlparse
import urllib2


iptables_flush="sudo iptables -F"
os.system(iptables_flush)
iptables_command="sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
#print iptables_command
os.system(iptables_command)

global tcp_seq
global tcp_ack
global file_name
global seq_data
global Tot_data
global tcp_seq_fin
global tcp_ack_fin
buffererdata= {}

#SOURCE IP

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('www.google.com',0))				# Determining Src Ip using Google.com
	src_name = s.getsockname()[0]
	#print 'src_name',src_name
	src_ip = socket.inet_aton(src_name)
except socket.error:
		print 'Socket Error Creation'
		s.close()
		sys.exit()



#tcp header fields
source_port=random.randint(10000,65000)
dest_port=80
sequence_number=random.randint(0,65535)
wnd_size=socket.htons(65535)
tcp_checksum=0
tcp_urg_ptr=0

#parsing hostname and path for the GET Request and saving the file name
url = sys.argv[1]


if "http://" not in url:
        url = "http://" + url
#print url 
host = urlparse(url)
hostname=host[1]
#print hostname

try:
	dst_name=socket.gethostbyname(hostname)
	#print 'Destination_name',dst_name
except socket.gaierror:
	print 'ENTER correct url.'
	sys.exit()
dst_ip = socket.inet_aton(dst_name)

path=host[2]
t=path.split('/')[-1:]
if path=='' or path[-1:]=="/":
 file_name='index.html'
else:
 file_name=t[0]

#print 'hostname=', hostname
#print 'filename=', file_name

#CHECK IF ARGUMENT IS NOT WORKING
if (len(sys.argv) !=2):
        print 'Enter valid arguments'
        sys.exit()


global cwnd
cwnd = 1
global ssthreshold
ssthreshold = 1000
global a
global b
def congestion_window():
		#when new ack arrives
		global cwnd
		global ssthreshold
		if cwnd <= ssthreshold:
			cwnd =cwnd+1
		else:
		     cwnd=cwnd/2
		     cwnd=cwnd+(1/cwnd)

def packet_retransmit(i):
			global cwnd
			global ssthreshold
			j=0
			ssthrehold=cwnd/2
			cwnd=1 	
			if i==0:	
				z=syn()
				syn_ack(z)
				i+=1
			elif (j==0 or i==1):
			     ack_send(previous_Data,previous_seq,previous_ack)			

def packet_loss(a,b):
		c=b-a
		if (c) > 180:
			print "Packet didnot arrive in 3 minutes,thus exiting"	
			sys.exit()
		elif (c) > 60:
			return c
	
			
					


def checksum_func(inp):
	data_len = len(inp)
	checksum=0
    	# loop taking 2 characters at a time
	if ((data_len%2)!=0):
		inp += chr(0)
    	for i in range(0, data_len, 2):
        	y = ord(inp[i]) + (ord(inp[i+1]) << 8 )
		checksum = checksum + y
	#if checksum contains the carry
	checksum = (checksum>>16) + (checksum &0xffff);
	checksum = checksum + (checksum >> 16);
        #complement and mask to 4 byte short
	checksum = ~checksum & 0xffff
    	return checksum

		


def tcp_header(src_ip,dst_ip,source_port,dest_port,data,sequence_number,ack_number,fin,syn,psh,ack,wnd_size=socket.htons(65535)):
	
	urg=0
	rst=0	
	data_offset=5
	tcp_flag=fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5) 
	tcp_offset_reserve=(data_offset << 4) + 0 
	tcp_header1=pack('!HHLLBBHHH' , source_port, dest_port, sequence_number, ack_number, tcp_offset_reserve, tcp_flag, wnd_size, 0, 0)
	reserved=0
	urg_ptr=0
	protocol=6
	tcp_length=len(tcp_header1) + len(data)
	psuedo_header=pack('!4s4sBBH',src_ip,dst_ip,reserved,protocol,tcp_length)
	psuedo_header1=psuedo_header + tcp_header1 + data
	tcp_checksum=checksum_func(psuedo_header1)
	#print "TCP_CHECKSUM in tcp header",tcp_checksum
	tcp_header2 = pack('!HHLLBBH' ,source_port,dest_port, sequence_number, ack_number, tcp_offset_reserve, tcp_flag, wnd_size) 
	tcp_header2 = tcp_header2 + pack('H' , tcp_checksum)	
	tcp_header2 = tcp_header2 + pack('!H' , urg_ptr)
	#print "HEADER IN SYN",len(tcp_header2)
	return tcp_header2

		

def ip_header(ip_proto, ip_ident, src_ip, dst_ip):
	ip_ident=54321
	ip_tos = 0
	ip_len = 0
	ip_ihl_ver = (4 << 4) + 5
	ip_proto = socket.IPPROTO_TCP
	ip_total = pack('!BBHHHBBH4s4s', ip_ihl_ver, 0, 0, ip_ident, 0, 255, ip_proto, 0, src_ip, dst_ip)
	checksum_ip = checksum_func(ip_total)	
	return pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_len, ip_ident, 0, 255, ip_proto, checksum_ip, src_ip, dst_ip)


def syn():
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error:
        	print 'SOCKET ERROR'
		sys.exit()
	data=''
	ip_header1=ip_header(socket.IPPROTO_TCP,54321,src_ip,dst_ip)
	tcp_header3=tcp_header(src_ip,dst_ip,source_port,dest_port,data,sequence_number,0,0,1,0,0,wnd_size)
	packet1=ip_header1+tcp_header3+data
	s.sendto(packet1,(dst_name,0))
	a = time.time()
	return a
	
	

def syn_ack(start_time):
	global tcp_seq
	global tcp_ack
	global dst_port
	global b
	a=start_time
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error:
        	print 'SOCKET ERROR'
		s.close()
		sys.exit()
	data = s.recvfrom(65535)
	b = time.time()
	data = data[0]
	#CHECKING PACKET LOSS
	c=packet_loss(a,b)
	if c>60:
		i=0	
		packet_retransmit(i)
	#ipheader extraction
	unpack_ipheader=unpack('!BBHHHBBH4s4s' , data[0:20])
	Ip_Ver_Hlen = unpack_ipheader[0] 				# first 8 bits (IP version + Header Length)
	Ip_Ver = Ip_Ver_Hlen >> 4				# shifting 4 bits to right to get IP Version number
	Ip_Hlen = Ip_Ver_Hlen & 0xF				# anding with 0xF to geth the header length
	Ip_Tot_Hlen = Ip_Hlen * 4
	Ip_totallength=unpack_ipheader[2]
	ip_src=socket.inet_ntoa(unpack_ipheader[8])
	ip_dst=socket.inet_ntoa(unpack_ipheader[9])
	#tcpheader extraction
	tcp_header_recv=data[Ip_Tot_Hlen : Ip_Tot_Hlen+20]
	unpack_tcpheader=unpack('!HHLLBBHHH' , data[Ip_Tot_Hlen : Ip_Tot_Hlen+20])
	#print "UNPACK TCP_HEADER",unpack_tcpheader
	tcp_seq =unpack_tcpheader[2]					# Sequence Number
	tcp_ack =unpack_tcpheader[3]	
	dst_prt = unpack_tcpheader[1]
	checksum_recv = unpack_tcpheader[7]
	#CHECKING FOR CHECKSUM
	data_packet = data[20:]
	Pseudo_Header_recv = pack('!4s4sBBH', src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(data_packet))
	Total_TCP_Header_recv= Pseudo_Header_recv + data_packet
	Checksum_recalc= checksum_func(Total_TCP_Header_recv)	
	if Checksum_recalc == 0:
		#print("CHECKSUM VALIDATED IN SYN-ACK")
		pass	
	return unpack_tcpheader



def ack():
	
	tcp_seq = unpack_tcpheader[2]					# Sequence Number
	tcp_ack = unpack_tcpheader[3]
	#print 'tcp_seq',tcp_seq
	#print 'tcp_ack',tcp_ack
	try:
		s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error:
       		 print 'SOCKET ERROR'
		 s1.close()
		 sys.exit()

	data=''
	tcp_header4=tcp_header(src_ip,dst_ip,source_port,dest_port,data,tcp_ack,tcp_seq+1,0,0,0,1,wnd_size)
	ip_header2=ip_header(socket.IPPROTO_TCP,54330,src_ip,dst_ip)
	packet2 = ip_header2+ tcp_header4+ data
	s1.sendto(packet2, (dst_name, 0))
	
	data1=("GET " +path+" HTTP/1.0\r\n"
		"Host: "+hostname+"\r\n"
		"Connection: keep-alive\r\n"
                "\r\n"
		)		
	if len(data1)% 2 != 0:
		data1 = data1 + " "
	tcp_header5=tcp_header(src_ip,dst_ip,source_port,dest_port,data1,tcp_ack,tcp_seq+1,0,0,1,1,wnd_size)
	ip_header3=ip_header(socket.IPPROTO_TCP,54320,src_ip,dst_ip)
	packet3=ip_header3+ tcp_header5+ data1
	s1.sendto(packet3, (dst_name, 0))
	ht_time =time.time()
	return ht_time
				


def fin(tcp_seq_fin,tcp_ack_fin):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error:
        	print 'SOCKET ERROR'
		s.close()
		sys.exit()

	data=''
	ip_header3=ip_header(socket.IPPROTO_TCP,54300,src_ip,dst_ip)
	tcp_header5=tcp_header(src_ip,dst_ip,source_port,dest_port,data,tcp_ack_fin,tcp_seq_fin+1,1,0,0,1,wnd_size)
	packet3=ip_header3+tcp_header5+data
	s.sendto(packet3,(dst_name,0))
	#print 'fin sent FIN SENT FIN SENT '
	try:
		s_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error:
		print "Socket Error"
		sys.exit()
	data = s_recv.recvfrom(64240)	
	data = data[0]
	unpack_ipheader=unpack('!BBHHHBBH4s4s' , data[0:20])
	Ip_Ver_Hlen = unpack_ipheader[0] 				
	Ip_Ver = Ip_Ver_Hlen >> 4				
	Ip_Hlen = Ip_Ver_Hlen & 0xF				
	Ip_Tot_Hlen = Ip_Hlen * 4
	Ip_totallength=unpack_ipheader[2]
	ip_src=socket.inet_ntoa(unpack_ipheader[8])
	ip_dst=socket.inet_ntoa(unpack_ipheader[9])
	#tcpheader extraction
	unpack_tcpheader=unpack('!HHLLBBHHH' , data[Ip_Tot_Hlen : Ip_Tot_Hlen+20])
	flags=unpack_tcpheader[5]
	if flags==16 or flags==25:
		s_recv.close()
		iptables_flush="sudo iptables -F"
		os.system(iptables_flush)
		sys.exit()
			
	
	
def extract(ht_time):
	global a
	global b
	global seq_data
	global tcp_flags
	global tcp_seq_fin
	global tcp_ack_fin
	final_recv_data=()
	j=0
	try:
		s_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error:
       		 print 'SOCKET ERROR'
		 sys.exit()

	while True:
		http=s_recv.recvfrom(65535)
		final_recv_data+=http
		http=http[0]
		b=time.time()
		#unpack ip header
		unpack_ipheader1=unpack('!BBHHHBBH4s4s' , http[0:20])
		Ip_Ver_Hlen1 = unpack_ipheader1[0] 				# first 8 bits (IP version + Header Length)
		Ip_Ver1 = Ip_Ver_Hlen1 >> 4				# shifting 4 bits to right to get IP Version number
		Ip_Hlen1 = Ip_Ver_Hlen1 & 0xF				# anding with 0xF to geth the header length
		Ip_Tot_Hlen1 = Ip_Hlen1 * 4
		Ip_totallength=unpack_ipheader1[2]		
		ip_src1=socket.inet_ntoa(unpack_ipheader1[8])
		ip_dst1=socket.inet_ntoa(unpack_ipheader1[9])	
		#tcpheader extraction
		unpack_tcpheader1=unpack('!HHLLBBHHH' , http[Ip_Tot_Hlen1 : Ip_Tot_Hlen1+20])
		tcp_seq1 =unpack_tcpheader1[2]					
		tcp_ack1 =unpack_tcpheader1[3]	
		dst_prt1 = unpack_tcpheader1[1]
		tcp_flags =unpack_tcpheader1[5]
		tcp_Hlen_Res = unpack_tcpheader1[4]                                     
		tcp_Hlen = tcp_Hlen_Res >> 4
		Tot_Header_Size = Ip_Tot_Hlen1 + tcp_Hlen * 4         
		Tot_data = len(http) - Tot_Header_Size
		Tot_data1 = http[Tot_Header_Size:]
		#CHECKING FOR CHECKSUM WHEN RECEIVE DATA FROM THE SERVER
		http_packet = http[20:]
		Pseudo_Header_recv1 = pack('!4s4sBBH', src_ip, dst_ip, 0, socket.IPPROTO_TCP, len(http_packet))
		Total_TCP_Header_recv1= Pseudo_Header_recv1 + http_packet
		Checksum_recalc1= checksum_func(Total_TCP_Header_recv1)	
		if Checksum_recalc1 == 0:
			#print("CHECKSUM VALIDATED WHEN DATA IS RECEIVE")
			pass
		else:
			z=0
			#print "WRONG CHECKSUM ENCOUNTERED"

		#print "Flags:",tcp_flags
		if (unpack_tcpheader[0]==dest_port and unpack_tcpheader[1]==source_port):
			if j==1:
				p=packet_loss(ht_time,b)
				if (total_ack==tcp_seq1 and Checksum_recalc1==0):
					#print "IN THE LOOP CHECK"
					if ( tcp_flags==17):
						#print "GOT THE FLAGS"
						if '200 OK' in final_recv_data[2]:
							#print "200 OK, okay"
							buffererdata[tcp_seq1]= Tot_data1
							makefile(buffererdata)
							fin(tcp_seq1,tcp_ack1)

						else:
							makefile(buffererdata)
							fin(tcp_seq1,tcp_ack1)

					elif '500' in final_recv_data[2]:
							print '500 Internal SERVER ERROR'
							sys.exit()
					elif '502' in final_recv_data[2]:
							print '502 BAD Gateway'
							sys.exit()
					elif '503' in final_recv_data[2]:
							print '503 SERVICE UNAVAILABLE'
							sys.exit()
					elif '403' in final_recv_data[2]:
							print '403 Forbidden ERROR'
							sys.exit()
					elif '404' in final_recv_data[2]:
							print '404 NOT FOUND'
							sys.exit()
					elif '301' in final_recv_data[2]:
							print '301 Moved Permanently'
							sys.exit()				
					elif(tcp_flags==25):
						#print "REACH FLAG 25"
						if len(Tot_data1):
							buffererdata[tcp_seq1]= Tot_data1
							#print "Buffer data1",buffererdata[tcp_seq1]
							makefile(buffererdata)
							fin(tcp_seq1,tcp_ack1)
						else:
							#print"No data"
							makefile(buffererdata) 
							fin(tcp_seq1,tcp_ack1)		
					else:
						if tcp_flags==4 or tcp_flags==20:
							sys.exit()
	 
						else:
							buffererdata[tcp_seq1]= Tot_data1
							#print "Buffer data3",buffererdata[tcp_seq1]
							global previous_Data
							global previous_seq
							global previous_ack
							previous_Data=Tot_data
							previous_seq=tcp_seq1
							previous_ack=tcp_ack1
							ack_send(previous_Data,previous_seq,previous_ack)
							total_ack=tcp_seq1+Tot_data
							congestion_window()
							ht_time=0
							ht_time=time.time()
				elif( total_ack!=tcp_seq1 and (p>60)):
					i=1					
					packet_retransmit(i)
					ht_time=0
					ht_time=time.time()
								
			else:
				j=j+1
				previous_Data=Tot_data
				previous_seq=tcp_seq1
				previous_ack=tcp_ack1
				#ack_send(previous_Data,previous_seq,previous_ack)	
				total_ack=tcp_seq1+Tot_data
				congestion_window()
			
					 

def ack_send(Tot_data,tcp_seq1,tcp_ack1):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	data=''
	tcp_header4=tcp_header(src_ip,dst_ip,source_port,dest_port,data,tcp_ack1,tcp_seq1+Tot_data,0,0,0,1,wnd_size)
	ip_header2=ip_header(socket.IPPROTO_TCP,54330,src_ip,dst_ip)
	packet2 = ip_header2+ tcp_header4+ data
	s.sendto(packet2, (dst_name, 0))
	#print 'ACK_SENT ACK'


def makefile(buffererdata):
                        ordered_tcp_seq = sorted(buffererdata.keys())
                        #print 'ordered_tcp_seq', ordered_tcp_seq
                        page = open(file_name, "w")
			#print buffererdata[ordered_tcp_seq[0]]
                        for k in ordered_tcp_seq:
                            if '\r\n\r\n' in buffererdata[k]:
                                d = buffererdata[k]
                                #print 'ddddddddddddddddddddd check check',d
                                page.writelines(d.split('\r\n\r\n')[1])
				#print "AFTER SPLIT",d
                            else:
                                page.writelines(buffererdata[k])
                        page.close() 	
	
start_time=syn()
unpack_tcpheader=syn_ack(start_time)
l=ack()
extract(l)
		




	


		





		

	












	
	

		
	





		


