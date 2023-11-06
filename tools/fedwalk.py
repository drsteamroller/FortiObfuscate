#! /usr/bin/env python3
# Description: 'Walk' through a directory and replace specified strings/IP addresses (FMG/FAZ backups are full directories containing DB backups)
# Author: Andrew McConnell
# Date:   5/4/2023

# FMG BACKUPS (7.2.2!!!!):
# /var/dvm/task/task.db is a DB (binary) file that will contain device data replacement should be possible
# /var/fwclienttemp/system.conf is a conf file of the FMG, data replacement is possible
# /var/pm2/ might contain some sensitive info

# FAZ 7.2.2 backups look to be the same

import sys
import re
import random
import os
from binascii import hexlify, unhexlify
from binaryornot.check import is_binary

# GLOBAL VARS

opflags = []
debug_mes = ""
depth = 0

str_repl = dict()
ip_repl = dict()
mac_repl = dict()

ip4 = re.compile(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ip4_bin = re.compile(b'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ip6 = re.compile(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
ip6_bin = re.compile(b"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")


# Helper Functions

# RFC1918 Detector
def isRFC1918(ip):
	a,b,c,d = ip.split('.')

	# Very explicitly checks if the addresses are RFC 1918 Class A/B/C addresses
	if (int(a) == 10):
		return(True)
	elif(int(a) == 172 and int(b) in range(16,32)):
		return(True)
	elif(int(a) == 192 and int(b) == 168):
		return(True)
	else:
		return(False)

# Check if valid IPv6 address
def isValidIP6(addr):
	if type(addr) == bytes:
		addr = str(addr)[2:-1]
	
	if len(addr) < 3:
		return False

	if " " in addr:
		return False
	
	maxcol = 7
	mincol = 2
	countcol = 0
	maxnums = 4
	countnums = 0
	validchars = re.compile(r'[A-Fa-f0-9:]')

	for num in addr:
		ch = validchars.search(num)
		if not ch:
			return False
		
		if num in ':':
			countcol += 1
			if countnums > maxnums:
				return False
			countnums = 0
		else:
			countnums += 1

	if countcol < mincol or countcol > maxcol:
		return False

	return True

# Subnet mask detector (Insert if needed)
'''
How it works:
1) Split the IP into a list of 4 numbers (we assume IPv4)
  a) expect_0 is set to True when we view a shift in 1's to 0's								V We set it to True so if there's a '1' after a '0', it's not a net_mask
													===> 255.255.240.0 = 11111111.11111111.11110000.00000000
  b) constant is a catch-all for when we detect it isn't (or is!!!) a net_mask, and we return it accordingly

2) We take each value in the ip_list and check if it's non zero
  a) If it's non zero, we subtract 2^i from that value where i is a list from 7 to 0 (decremented).
	i) If the value hits zero during this process and i is not zero, set expect_0 to True and break out of the process [val is zero so we don't need to subtract any more]
	ii) If the value hits zero during the process and i IS zero (255 case), we continue to the next value
	###### IF AT ALL DURING THIS PROCESS THE VALUE GOES BELOW ZERO, WE SET constant = False AND BREAK AND 'return constant' ######
  b) If the value starts out as zero, we don't bother with the process and just set expect_0 to True (catches 255.0.255.0 and similar cases)
'''
def isNetMask(ip):
	_ = ip.split('.')
	ip_list = list()
	for item in _:
		try:
			ip_list.append(int(item))
		except ValueError as e:
			print(f"[FEDWALK] Error interpreting IP: {ip}, continuing")
			return True # Return true to not mess with IP (or falsely flagged IP)

	# Return false for quad 0 case (default routes)
	if (ip_list == [0,0,0,0]):
		return False

	# Netmasks ALWAYS start with 1's
	expect_0 = False
	# We start out assuming constancy
	constant = True

	for val in ip_list:
		if (val != 0):
			for i in range(7, -1, -1):
				val = val - pow(2, i)
				if (val > 0 and not expect_0):
					continue
				elif (val == 0  and i != 0):
					expect_0 = True
					break
				elif (val == 0 and not expect_0 and i == 0):
					break
				else:
					constant = False
					break
			if (not constant):
				break
		else:
			expect_0 = True
	return constant

# Mask IPs
def replace_ip4(ip):
	if (ip in ip_repl.keys()):
		return ip_repl[ip]
	
	if (isNetMask(ip)):
		return ip
	if (ip not in ip_repl.keys()):
		repl = ""
		if (isRFC1918(ip) and "-sPIP" in opflags and "-pi" not in opflags):
			octets = ip.split('.')
			repl = f"{octets[0]}.{octets[1]}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
		elif (not isRFC1918(ip) and "-pi" not in opflags):
			repl = f"{random.randrange(1, 255)}.{random.randrange(0, 255)}.{random.randrange(0, 255)}.{random.randrange(1, 255)}"
		else:
			repl = ip
		ip_repl[ip] = repl
		return repl
	
	# If we've replaced it before, pick out that replacement and return it
	else:
		return ip_repl[ip]

def replace_ip6(ip):

	if not isValidIP6(ip):
		return ip
	
	if (ip not in ip_repl.keys() and "-pi" not in opflags):
		repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
		ip_repl[ip] = repl
		return repl
	elif ("-pi" not in opflags):
		return ip_repl[ip]
	else:
		return ip

def replace_str(s):
	if s in str_repl.keys():
		return str_repl[s]
	
	return s

def repl_dicts_to_logfile(filename):
	with open(filename, 'w') as outfile:
		outfile.write("+---------- MAPPED IP ADDRESSES ----------+\n")
		for og, rep in ip_repl.items():
			outfile.write(f"Original IP: {og}\nMapped IP: {rep}\n\n")
		outfile.write("+---------- MAPPED MAC ADDRESSES ---------+\n\n")

		outfile.write("+---------- MAPPED STRING VALUES ---------+\n")
		for og, rep in str_repl.items():
			outfile.write(f"Original String: {og}\nMapped String: {rep}\n\n")
		
	print(f"Mapped address outfile written to: {filename}")

mtd = ""

# Grab all directories going 'depth' number of steps deep
# Opens a new directory to write modified files to
def buildDirTree(dir):
	mod_dir = f"{dir}_obfuscated"

	mtd = mod_dir

	dirTree = next(os.walk(dir))[0]
	slashes = dirTree.count('/') + dirTree.count('\\')

	dirTree = []

	for dirpath, dirnames, fnames in os.walk(dir):
		check = f"{dirpath}"

		if ((check.count('/') + check.count('\\')) - slashes) > depth:
			continue
		
		dirTree.append(check)

	# Create new directory to house the modified files
	os.makedirs(mod_dir, exist_ok=True)

	moddirTree = dirTree.copy()
	for i, path in enumerate(moddirTree):
		a = re.search(dir, path)
		moddirTree[i] = path[:a.span()[0]] + mod_dir + path[a.span()[1]:]

		os.makedirs(moddirTree[i], exist_ok=True)
	
	return (mtd, dirTree)

def getFiles(dirTree):
	slash = '/'

	files = []
	# Gotta love Windows
	if sys.platform == 'win32':
		slash = '\\'
	
	# list comprehension ftw! dir + slash (/ or \) + filename
	for dir in dirTree:
		files.extend([f'{dir}{slash}{i}' for i in next(os.walk(dir))[2]])
		if f'{dir}{slash}fedwalk.py' in files:
			print(f"\nERROR: You cannot perform a fedwalk on a directory containing itself\n\nexiting...\n")
			sys.exit()
	
	return files

def modifyTxtFile(txtfile, debug_log: str):
	if type(txtfile) != list:
		return txtfile

	for i, line in enumerate(txtfile):
		
		for k in ip_repl.keys():
			ipsearch = re.findall(k, line)
			if ipsearch:
				for ip in ipsearch:
					line = line.replace(ip, replace_ip4(ip))
					debug_log += f"[FEDWALK_txt] \\ipv4\\ identified and replaced:\n\t{ip} -> {replace_ip4(ip)}\n"
		
		ipsearch = ip4.findall(line)
		
		if ipsearch:
			# Doctor the findings so it's easier to replace
			ph = []
			for z in ipsearch:
				ph.append(f"{z[0]}.{z[1]}.{z[2]}.{z[3]}")
			ipsearch = ph

			# actually replace
			for ip in ipsearch:
				line = line.replace(ip, replace_ip4(ip))
				debug_log += f"[FEDWALK_txt] \\ipv4 address\\ identified and replaced:\n\t{ip} -> {replace_ip4(ip)}\n"
		

		ip6search = ip6.findall(line)
		
		if ip6search:
			ph = []
			for z in ip6search:
				s = [f"{p}" for p in z]
				ph.append(s[0])
			ip6search = ph

			for i6 in ip6search:
				line = line.replace(i6, replace_ip6(i6))
				debug_log += f"[FEDWALK_txt] \\ipv6 address\\ identified and replaced:\n\t{i6} -> {replace_ip6(i6)}\n"

		
		for k in str_repl.keys():
			strsearch = re.findall(k, line)
			if strsearch:
				for ss in strsearch:
					line = line.replace(ss, replace_str(ss))
					debug_log += f"[FEDWALK_txt] \\string\\ identified and replaced:\n\t{ss} -> {replace_str(ss)}\n"
		
		txtfile[i] = line

	return txtfile

def modifyBinFile(binfile, debug_log):
	if type(binfile) != list:
		return binfile

	for i, line in enumerate(binfile):
		
		bipsearch = ip4_bin.findall(line)
		
		reconstruct = []
		for boct in bipsearch:
			bip = bytes(f"{str(boct[0])[2:-1]}.{str(boct[1])[2:-1]}.{str(boct[2])[2:-1]}.{str(boct[3])[2:-1]}", encoding="utf-8")
			reconstruct.append(bip)

		bipsearch = reconstruct
		for bip in bipsearch:
			strrep = str(bip)[2:-1]
			repl = bytes(replace_ip4(strrep), 'utf-8')
			line = line.replace(bip, repl)
			debug_log += f"[FEDWALK_bin] \\ipv4 address\\ identified and replaced:\n\t{bip[2:-1]} -> {repl[2:-1]}\n"

		
		binfile[i] = line

	return binfile

def importStrs(filename):
	lines = []
	with open(filename, 'r') as st:
		lines = st.readlines()
	
	if len(lines) == 1 and ',' in lines[0]:
		lines = lines[0].split(',')
	
	for s in lines:
		replace_str(s.strip('\n '))

def importMap(filename):
	lines = []
	with open(filename, 'r') as o:
		lines = o.readlines()

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
				OG = components[1].strip()
			else:
				ip_repl[OG] = components[1].strip()
				OG = ""
		elif imp_mac:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1].strip()
			else:
				#mac_repl[OG] = components[1]
				OG = ""
		elif imp_str:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1].strip()
			else:
				str_repl[OG] = components[1].strip()
				OG = ""
		
		else:
			print("Something went wrong, mappings might not be fully imported\n")
			print(f"Interpreted mappings based on import\nIP Mapping: {ip_repl}\nMAC Mapping:\nString Mapping: {str_repl}\n")

options = {"-h": "Display this output",\
		   "-sPIP": "Scrub private IPs. Assumes /16 subnet",\
		   "-pi":"preserve all ip addresses",\
		   "-pm":"preserve MAC addresses",\
		   "-st=<stringfile>:":"Import a file containing strings you wish to replace (csv or newline separated values)",\
		   "-map=<mapfilename>":"Import IP/MAC/String mappings from other FFI program output"}

def mainloop(args: list, src_path: str, dst_path: str, debug_log: __file__):

	global opflags
	global debug_mes
	opflags = args
	
	contents = None
	r_mode = ''
	w_mode = ''

	if is_binary(src_path):
		r_mode = 'rb'
		w_mode = 'wb'
	else:
		r_mode = 'r'
		w_mode = 'w'

	with open(src_path, r_mode) as rf:
		contents = rf.readlines()

	if r_mode == 'rb':
		contents = modifyBinFile(contents, debug_mes)
	
	else:
		contents = modifyTxtFile(contents, debug_mes)
	
	with open(dst_path, w_mode) as wf:
		wf.writelines(contents)

	if debug_log:
		debug_log.write(debug_mes + "\n\n")
		debug_mes = ""