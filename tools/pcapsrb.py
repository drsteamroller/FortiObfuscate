#!/usr/bin/env python3
#############################################################################################
#                 PCAP sanitization for Federal customers
# Usage:
#		pcapsrb.py [file].pcap [options]
#		
# Options:
#		--help : Shows these options
#		-pm, --preserve-macs : Skips MAC address scramble
#		-pi, --preserve-ips : Skips IP address scramble
#		-sPIP, --scramble-priv-ips : Scramble RFC 1918 (private) IP addresses
#		-O=<OUTFILE> : Output file name for log file, which shows the ip/mac address mappings
#		-sp, --scrub-payload : Unintelligently* scrambles all data past TCP/UDP header info [*Not protocol-aware] 
#
# Author: Andrew McConnell
# Date:   03/09/2023
#############################################################################################

import sys
import dpkt
import random
import datetime
import ipaddress
import binascii

# Global Variables
ip_repl = dict()
mac_repl = dict()
str_repl = dict()
protocol_ports = {'dhcp': [67,68], \
		  'tftp': [69], 'http': [80], 'dhcpv6': [546,547], 'radius': [1812,1813]}
opflags = []
mapfilename = ""

#############################################################################################
#                                    Helper Functions                                       #
#############################################################################################

def isRFC1918(ip):
	hexd = ip.hex()
	if (hexd >= 'ac100000' and hexd <= 'ac20ffff'):
		return True
	elif (hexd >= 'c0a80000' and hexd <= 'c0a8ffff'):
		return True
	elif (hexd >= '0a000000' and hexd <= '0affffff'):
		return True
	else:
		return False
	
# Replaces IPs, but the same IP gets the same replacement
# >> I.E. 8.8.8.8 always replaces to (randomized) 144.32.109.200 in the pcap
# The point of these replacement commands is to make sure the same IP/MAC has the same replacement
def replace_ip(ip):
	# Account for broadcast/quad 0
	if (type(ip) is str):
		ip = bytes.fromhex(ip)
	if ((ip.hex()[-2:] == 'f'*2) or (ip.hex() == '0'*8)):
		return ip
	if(isRFC1918(ip) and ('-sPIP' not in opflags and '--scramble-priv-ips' not in opflags)):
		return ip			

	if (ip not in ip_repl.keys()):
		repl = ""
		if(isRFC1918(ip)):
			repl = ip.hex()[0:4]
			for h in range(4):
				i = random.randint(0,15)
				repl += f"{i:x}"
		else:
			for g in range(8):
				i = random.randint(0,15)

				# PREVENTS 0.X.X.X ADDRESSES
				while ((i + g) == 0):
					i = random.randint(0,15)

				repl += f'{i:x}'

		ip_repl[ip] = repl
		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip])

# Literally the same function as IPv4, except generates a longer address
def replace_ip6(ip6):
	# Account for broadcast/zero'd addresses
	if (ip6.hex() == 'f'*32 or ip6.hex() == '0'*32):
		return ip6

	if (ip6 not in ip_repl.keys()):
		repl = ""
		for g in range(32):
			i = random.randint(0,15)
			repl += f'{i:x}'

			# PREVENTS 0:: ADDRESSES
			while ((i + g) == 0):
				i = random.randint(0,15)

		ip_repl[ip6] = str(repl)

		# Re-encode the output into bytes
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(ip_repl[ip6])

# Same philosophy, but with mac addresses
def replace_mac(mac):
	# Account for broadcast/zero'd addresses
	if (mac.hex() == 'f'*12 or mac.hex() == '0'*12):
		return mac
	
	if (mac.hex() not in mac_repl.keys()):
		repl = ""
		for g in range(12):
			i = random.randint(0,15)
			repl += f'{i:x}'
		mac_repl[mac.hex()] = repl
		return bytearray.fromhex(repl)
	else:
		return bytearray.fromhex(mac_repl[mac.hex()])

def replace_str(s):
	if s in str_repl.keys():
		return str_repl[s]
	
	repl = ""
	for l in s:
		c = 0
		
		if (random.random() > .5):
			c = chr(random.randint(65,90))
		else:
			c = chr(random.randint(97, 122))

		repl += c
	str_repl[s] = repl

	return repl

# takes TCP/UDP packet data and determines/scrubs the data based on standard ports
def scrub_upper_prots(pkt, sport, dport):
	# UDP only protocols
	#	TFTP <
	# 	I need to track the ports after the first request, since the server picks an ephemeral port after the first request packet
	if (sport in protocol_ports['tftp'] or dport in protocol_ports['tftp']):
		pkt = dpkt.tftp.TFTP(pkt)

		# Sort of keep track of new tftp sessions
		if (dport == 69):
			protocol_ports['tftp'].append(sport)
		mask = ""
		for g in range(len(pkt.data)*2):
			i = random.randint(0,15)
			mask += f"{i:x}"
		pkt.data = bytes.fromhex(mask)

	# 	DHCP <
	elif (sport in protocol_ports['dhcp'] or dport in protocol_ports['dhcp']):
		try:
			pkt = dpkt.dhcp.DHCP(pkt)

			# Since dpkt's DHCP module interprets ips as ints, we have to do this
			c = hex(pkt.ciaddr)[2:]
			c = '0'*(8-len(c)) + c
			y = hex(pkt.yiaddr)[2:]
			y = '0'*(8-len(y)) + y
			s = hex(pkt.siaddr)[2:]
			s = '0'*(8-len(s)) + s
			g = hex(pkt.giaddr)[2:]
			g = '0'*(8-len(g)) + g #											} F
		#																		} M
			# This works 														} L
			pkt.ciaddr = int.from_bytes(replace_ip(c), "big")
			pkt.yiaddr = int.from_bytes(replace_ip(y), "big")
			pkt.siaddr = int.from_bytes(replace_ip(s), "big")
			pkt.giaddr = int.from_bytes(replace_ip(g), "big")
			pkt.chaddr = replace_mac(pkt.chaddr)

			# the DHCP options are encoded as a tuple (of tuples).
			# In order to mutate the content, we need to convert the tuple of tuples to a list of lists
			options = []
			for i in range(len(pkt.opts)):
				innerlist = []
				# Structure as ((Option1, Data), (Option2, Data) ...) so we don't need to nest for loops
				innerlist.append(pkt.opts[i][0])
				innerlist.append(pkt.opts[i][1])
				options.append(innerlist)

			for i in range(len(options)):

				# option 3 (Untested)
				if (options[i][0] == 3):
					ip = replace_ip(options[i][1])
					options[i][1] = ip
				
				# option 6 (Untested)
				elif (options[i][0] == 6):
					ip = replace_ip(options[i][1])
					options[i][1] = ip

				# option 7 (Untested)
				elif (options[i][0] == 7):
					ip = replace_ip(options[i][1])
					options[i][1] = ip
				
				# option 12 (Untested)
				elif (options[i][0] == 12):
					swap = ""
					for g in range(len(options[i][1]) * 2):
						h = random.randint(0, 15)
						swap += f"{h:x}"
					options[i][1] = bytearray.fromhex(swap)
				
				# option 15 (Untested)
				elif (options[i][0] == 15):
					swap = ""
					for g in range(len(options[i][1]) * 2):
						h = random.randint(0, 15)
						swap += f"{h:x}"
					options[i][1] = bytearray.fromhex(swap)

				# option 50
				elif (options[i][0] == 50):
					ip = replace_ip(options[i][1])
					options[i][1] = ip

				# option 54
				elif (options[i][0] == 54):
					ip = replace_ip(options[i][1])
					options[i][1] = ip

				# option 61
				elif (options[i][0] == 61):
					length = options[i][1][:1]
					mac = replace_mac(options[i][1][1:])
					options[i][1] = length + mac

			# probably isn't necessary, but why not
			pkt.opts = tuple(options)
		except Exception as e:
			return pkt

	# HTTP request (does not work)
	elif (dport in protocol_ports['http']):
		ogpkt = pkt
		mes = None
		try:
			mes = dpkt.http.Message(pkt)
			pkt = dpkt.http.Request(mes)
		except Exception as e:
			return ogpkt
		swap = ""
		for g in range(len(pkt.body) * 2):
			h = random.randint(0,15)
			swap += f"{h:x}"
		print(pkt.Message)
		pkt.body = bytearray.fromhex(swap)
	
	# http response (does not work)
	elif (sport in protocol_ports['http']):
		ogpkt = pkt
		mes = None
		try:
			mes = dpkt.http.Message(pkt)
			pkt = dpkt.http.Response(mes)
		except:
			return ogpkt
		print(pkt.uri)
		swap = ""
		for g in range(len(pkt.body) * 2):
			h = random.randint(0,15)
			swap += f"{h:x}"
		print(pkt.body)
		pkt.body = bytearray.fromhex(swap)
	
	elif (sport in protocol_ports['radius'] or dport in protocol_ports['radius']):
		pkt = dpkt.radius.RADIUS(pkt)

		total_len = 20
		# Convert the tuples into a list so we can manipulate values
		attrlist = []
		for t, d in pkt.attrs:
			attrlist.append([t,d])

		for off, [t, d] in enumerate(attrlist):
			print(f"Before: {d}")
			if t == dpkt.radius.RADIUS_USER_NAME:
				d = bytes(replace_str(d), 'utf-8')
			
			elif t == dpkt.radius.RADIUS_NAS_IP_ADDR:
				d = replace_ip(d)
			
			elif t == dpkt.radius.RADIUS_FRAMED_IP_ADDR:
				if (b'.' in d):
					d = replace_ip(d)
			
			elif t == dpkt.radius.RADIUS_REPLY_MESSAGE or t == 79:
				for st in str_repl.keys():
					if st in d:
						d = d.replace(st, bytes(replace_str(st), 'utf-8'))
			
			elif t == dpkt.radius.RADIUS_CALLED_STATION_ID or t == dpkt.radius.RADIUS_CALLING_STATION_ID:
				if (b'-' in d):
					macstr = ""
					nodash = ""
					for i in d:
						macstr += chr(i)
					
					# Get rid of dashes
					for i in range(len(macstr)):
						if ((i-2) % 3 != 0):
							nodash += macstr[i]

					nodash = binascii.unhexlify(nodash)	

					b = replace_mac(nodash)

					macstr = ""
					nodash = ""
					for i in b:
						macstr += hex(i)[2:]

					stupid = -2
					# Add dashes back
					for h in range(len(macstr)):
						if ((h+stupid) % 3 == 0):
							stupid +=1
							nodash += "-"
						nodash += macstr[h].upper()

					if (len(nodash) < 17): nodash += '0'
					
					d = nodash
				else:

					d = str(d)[2:-1]

					octets = d.split('.')
					hexrep = ""
					for o in octets:
						h = hex(int(o))[2:]
						if (len(h) < 2):
							hexrep += '0' + h
						else:
							hexrep += h
					
					# replace, but also convert back to a hex string so we can properly swap back to a byte string
					replaced = str(binascii.hexlify(replace_ip(binascii.unhexlify(hexrep))))[2:-1]
					
					r = ""
					for w in range(0, len(replaced), 2):
						r += str(int(replaced[w]+replaced[w+1], 16)) + '.'
					
					r = r[:-1]

					d = bytes(r, 'utf-8')

			elif t == dpkt.radius.RADIUS_NAS_ID:
				d = bytes(replace_str(d), 'utf-8')
			
			elif t == 44:
				d_str = str(d)[2:-1]
				for st in str_repl.keys():
					st_s = str(st)[2:-1]
					if st_s in d_str:
						d_str = d_str.replace(st_s, replace_str(st))
				
				d = bytes(d_str, 'utf-8')

			elif t == 66:
				d = str(d)[2:-1]

				octets = d.split('.')
				hexrep = ""
				for o in octets:
					h = hex(int(o))[2:]
					if (len(h) < 2):
						hexrep += '0' + h
					else:
						hexrep += h
				
				# replace, but also convert back to a hex string so we can properly swap back to a byte string
				replaced = str(binascii.hexlify(replace_ip(binascii.unhexlify(hexrep))))[2:-1]
				
				r = ""
				for w in range(0, len(replaced), 2):
					r += str(int(replaced[w]+replaced[w+1], 16)) + '.'
				
				r = r[:-1]

				d = bytes(r, 'utf-8')
			
			attrlist[off] = [t, d]

		for off, [t, d] in enumerate(attrlist):
			len_d = len(d) + 2
			total_len += len_d
			preamble = 0
			data = 0
			#print(f"Type: {t}, Length: {len_d}, Data: {d}")

			preamble = hex(int(t))[2:].zfill(2) +\
						hex(int(len_d))[2:].zfill(2)
			
			if type(d) == str:
				data = bytes(d, 'utf-8')
			
			else:
				data = d

			data = binascii.unhexlify(preamble) + data

			pkt.data += data

		pkt.len = total_len

	return pkt

# Mappings file, takes the replacement dictionaries "ip_repl" and "mac_repl" and writes them to a file for easy mapping reference
def repl_dicts_to_logfile(filename):
	with open(filename, 'w') as outfile:
		outfile.write("+---------- MAPPED IP ADDRESSES ----------+\n")
		for og, rep in ip_repl.items():
			rep = int(rep, 16)
			if (len(og.hex()) <= 12):
				OGaddress = str(ipaddress.IPv4Address(og))
				SPaddress = str(ipaddress.IPv4Address(rep))
			else:
				OGaddress = str(ipaddress.IPv6Address(og))
				SPaddress = str(ipaddress.IPv6Address(rep))
			outfile.write(f"Original IP: {OGaddress}\nMapped IP: {SPaddress}\n\n")
		outfile.write("+---------- MAPPED MAC ADDRESSES ---------+\n")
		for og, rep in mac_repl.items():
			formatOG = ""
			for x in range(1, len(og), 2):
				formatOG += og[x-1] + og[x] + ':'
			formatREP = ""
			for y in range(1, len(rep), 2):
				formatREP += rep[y-1] + rep[y] + ':'
			formatOG = formatOG[:-1]
			formatREP = formatREP[:-1]
			outfile.write(f"Original MAC: {formatOG}\nMapped MAC: {formatREP}\n\n")
		outfile.write("+---------- MAPPED STRING VALUES ---------+\n")
		for og, rep in str_repl.items():
			outfile.write(f"Original String: {str(og)[2:-1]}\nMapped String: {rep}\n\n")
	print(f"Mapped address outfile written to: {filename}")

def importMap(filename):
	lines = []
	with open(filename, 'r') as o:
		lines = o.readlines()
	
	print(lines)

	imp_ip = False
	imp_mac = False
	imp_str = False

	OG = ""
	for l in lines:
		if '+---' in l:
			if 'IP' in l:
				imp_ip = True
				imp_mac = False
				imp_str = False
			elif 'MAC' in l:
				imp_ip = False
				imp_mac = True
				imp_str = False
			elif 'STRING' in l:
				imp_ip = False
				imp_mac = False
				imp_str = True
			else:
				print("Map file is improperly formatted, do not make changes to the map file unless you know what you are doing")
				sys.exit(1)
			continue

		if not len(l):
			continue

		if imp_ip:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1]
			else:
				ip_repl[OG] = components[1]
				OG = ""
		elif imp_mac:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1]
			else:
				mac_repl[OG] = components[1]
				OG = ""
		elif imp_str:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1]
			else:
				str_repl[OG] = components[1]
				OG = ""
		
		else:
			print("Something went wrong, mappings might not be fully imported\n")
			print(f"Interpreted mappings based on import\nIP Mapping: {ip_repl}\nMAC Mapping: {mac_repl}\nString Mapping: {str_repl}\n")
		

#############################################################################################
#                                       CLI ARGS Setup                                      #
#############################################################################################

# Include private IP scramble
options = {"-pi, --preserve-ips":"Program scrambles routable IP(v4&6) addresses by default, use this option to preserve original IP addresses",\
		   "-pm, --preserve-macs":"Disable MAC address scramble",\
			"-sPIP, --scramble-priv-ips":"Scramble private/non-routable IP addresses",\
			"-O=<OUTFILE>":"Output file name for log file, which shows the ip/mac address mappings",\
			"-sp, --scrub-payload":"Sanitize payload in packet (DHCP/TFTP supported, HTTP under construction)",\
			"-ns":"Non-standard ports used. By default pcapsrb.py assumes standard port usage, use this option if the pcap to be scrubbed uses non-standard ports. For more info on usage, run \'python pcapsrb.py -ns -h\'",\
			"-map=<MAPFILE>":"Take a map file output from any FFI program and input it into this program to utilize the same replacements"}

def mainLoop(args: list, src_path: str, dst_path: str):

	# Check if file is included
	if (len(args) < 2):
		print("\nUsage:\n\tpy pcapsrb.py [file].pcap [options]\n\t--help -> for options\n")
		sys.exit()

	if ('-h' in args[1]):
		for k,v in options.items():
			print("\t{}: {}".format(k, v))
		sys.exit()

	elif (len(args) > 2 and '-ns' in args[1] and '-h' in args[2]):
		print("Refer to the example file in the GitHub called \'ports.txt\'. Use this example file or do an -ns=<file> to feed in a custom file.\
		\nIf you just do a \'-ns\' with no equal, it will assume you are referring to ports.txt for non-standard ports.\n\
			The protocols in ports.txt are the only protocols that are scrubbed. You can add more, however, they will not be scrubbed\n\
			If you want to leave certain protocols un-scrubbed, you can set their port to -1, and it will be ignored\n")
		sys.exit()

	else:
		if('.pcap' not in args[1]):
			print("Unsupported file format: \"{}\"\nRun python pcapsrb.py -h for usage help\n".format(args[1]))
			sys.exit()

	# Grab the args and append them into a flags list. Do some special operations for -O and -ns flags
	ports = ""
	for arg in args[2:]:
		if ("-O=" in arg):
			try:
				mapfilename = arg.split("=")[1]
			except:
				print("-O option needs to be formatted like so:\n\t-O=<filename>")
			continue
		if ("-ns" in arg):
			if ('=' in arg):
				ports = arg.split("=")[1]
			else:
				ports = "ports.txt"
			mappings = []
			try:
				with open(ports, 'r') as pfile:
					mappings = pfile.readlines()
			except:
				print(f"\n** Specified non-standard ports file ({ports}) not present, using default ports **\n")	
			for entry in mappings:
				print(entry)
				try:
					prot_port = entry.split(':')
					prot_port[1] = prot_port[1].strip('[]\n')
					if (',' in prot_port[1]):
						protocol_ports[prot_port[0].lower()] = prot_port[1].split(',')
					else:
						protocol_ports[prot_port[0].lower()] = [prot_port[1]]
				except:
					print("Non-standard ports file not formatted correctly\nCorrect format:\n\n<Protocol1>:<port>\n<Protocol2>:<port>\n...\nSee ports.txt for more examples")
		if ("map=" in arg):
			try:
				fn = arg.split('=')[1]
				importMap(fn)
			except FileNotFoundError as e:
				print(f"Could not find file/path specified: '{fn}'")
			except IndexError:
				print("-map option needs to be formatted like so:\n\t-map=<filename>")
			except:
				print("Something went wrong when importing mapfile (-map=<file> option)")
		opflags.append(arg)

	# Open the existing PCAP in a dpkt Reader
	try:
		f = open(args[1], 'rb')
	except:
		print("File not found or something else went wrong, try full path or place pcapsrb.py & pcap in same path")
		sys.exit()
	pcap = dpkt.pcap.Reader(f)

	# Open a dpkt Writer pointing to an output file
	modfilename = "{}_mod.pcap".format(args[1].split('.')[0])
	f_mod = open(modfilename, 'wb')
	pcap_mod = dpkt.pcap.Writer(f_mod)

	#############################################################################################
	#                                  Enter PCAP Scrubbing                                     #
	#############################################################################################

	print("Entering pcap", end='')

	for timestamp, buf in pcap:
		try:
			# unpack into (mac src/dst, ethertype)
			eth = dpkt.ethernet.Ethernet(buf)
			
			# Replace MAC addresses if not flagged
			if("-pm" not in opflags and "--preserve-macs" not in opflags):
				eth.src = replace_mac(eth.src)
				eth.dst = replace_mac(eth.dst)

			# Replace IP addresses if not flagged
			if (isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6)):
				ip = eth.data
				if("-pi" not in opflags and "--preserve-ips" not in opflags):
					if (len(ip.src.hex()) == 8):
						ip.src = replace_ip(ip.src)
					else:
						ip.src = replace_ip6(ip.src)
					if (len(ip.dst.hex()) == 8):
						ip.dst = replace_ip(ip.dst)
					else:
						ip.dst = replace_ip6(ip.dst)

				# Check for ICMP/v6. Currently testing to see what needs to be masked
				if (isinstance(ip.data, dpkt.icmp.ICMP)):
					icmp = ip.data
					# print('ICMP data: %s' % (repr(icmp.data)))

				if (isinstance(ip.data, dpkt.icmp6.ICMP6)):
					icmp6 = ip.data
					# print('ICMP6 data: %s' % (repr(icmp6.data)))
					chk = icmp6.data
					icmp6cl = dpkt.icmp6.ICMP6
					if (isinstance(chk, icmp6cl.Error) or isinstance(chk, icmp6cl.Unreach) or isinstance(chk, icmp6cl.TimeExceed) or isinstance(chk, icmp6cl.ParamProb)):
						pass
					else:
						pass
						# Need to figure out how to access router advertisements, might be wise just to scrub the whole payload
						'''mask = ""
						for g in range(len(icmp6.data)*2):
							i = random.randint(0,15)
							mask += f"{i:x}"
						icmp6.data = bytes.fromhex(mask)'''

				# TCP instance, preserve flags - possibly overwrite payload
				if (isinstance(ip.data, dpkt.tcp.TCP) and ip.p == 6):
					if ('-sp' in opflags or '--scrub-payload' in opflags):
						tcp = ip.data
						tcp.data = scrub_upper_prots(tcp.data, tcp.sport, tcp.dport)

				# UDP instance, possibly overwrite payload
				if (isinstance(ip.data, dpkt.udp.UDP) and ip.p == 17):
					if ('-sp' in opflags or '--scrub-payload' in opflags):
						udp = ip.data
						udp.data = scrub_upper_prots(udp.data, udp.sport, udp.dport)

			# Replace ARP ethernet & ip address info
			elif (isinstance(eth.data, dpkt.arp.ARP) and eth.type == 2054):
				arp = eth.data
				if("-pm" not in opflags and "--preserve-macs" not in opflags):
					# Replace source/destination mac in arp data body
					arp.sha = replace_mac(arp.sha)
					arp.tha = replace_mac(arp.tha)
				if("-pi" not in opflags and "--preserve-ips" not in opflags):
					if (len(arp.spa.hex()) <= 12):
						arp.spa = replace_ip(arp.spa)
					else:
						arp.spa = replace_ip6(arp.spa)
					if (len(arp.tha.hex()) <= 12):
						arp.tpa = replace_ip(arp.tpa)
					else:
						arp.tpa = replace_ip6(arp.tpa)			

			else:
				try:
					eth = dpkt.ip.IP(buf)
					ip = eth
					if("-pi" not in opflags and "--preserve-ips" not in opflags):
						if (len(ip.src.hex()) == 8):
							ip.src = replace_ip(ip.src)
						else:
							ip.src = replace_ip6(ip.src)
						if (len(ip.dst.hex()) == 8):
							ip.dst = replace_ip(ip.dst)
						else:
							ip.dst = replace_ip6(ip.dst)
					
					# TCP instance, preserve flags - possibly overwrite payload
					if (isinstance(ip.data, dpkt.tcp.TCP) and ip.p == 6):
						if ('-sp' in opflags or '--scrub-payload' in opflags):
							tcp = ip.data
							tcp.data = scrub_upper_prots(tcp.data, tcp.sport, tcp.dport)

					# UDP instance, possibly overwrite payload
					if (isinstance(ip.data, dpkt.udp.UDP) and ip.p == 17):
						if ('-sp' in opflags or '--scrub-payload' in opflags):
							udp = ip.data
							udp.data = scrub_upper_prots(udp.data, udp.sport, udp.dport)
				except:
					print("Packet at timestamp: {} is of non IP Packet type, therefore unsupported (as of right now)".format(datetime.datetime.utcfromtimestamp(timestamp)))

			# Write the modified (or unmodified, if not valid) packet
			pcap_mod.writepkt(eth, ts=timestamp)

			# each '.' means one packet read&written
			print(".", end='')

		except Exception as e:
			print(f"Exception thrown at timestamp {datetime.datetime.utcfromtimestamp(timestamp)}: {e}")
			pcap_mod.writepkt(eth, ts=timestamp)

	print()

	try:
		if (len(mapfilename) == 0):
			mapfilename = args[1].split('.')[0] + "_mpdaddr.txt"

		repl_dicts_to_logfile(mapfilename)
	finally:
		f.close()
		f_mod.close()