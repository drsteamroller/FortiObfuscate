#!/usr/bin/env python3
# Description - On the way
# Author: Andrew McConnell
# Date:   04/04/2023

import random
import re
import sys
import os

# GLOBAL VARS
# Log content is a list of dictionaries if one log is supplied, and if multiple are supplied,
# then it is a list of lists of dictionaries
logcontents = []
# list of filenames
og_filenames = []
mod_filenames = []
mod_dir = ""
opflags = []
str_repl = dict()
ip_repl = dict()
syslogregex = re.compile(r'(.+?)=("[^"]*"|\S*)\s*')
ip4 = re.compile(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ip6 = re.compile(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")

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
		ip_list.append(int(item))

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

	repl = ""
	for ch in s:
		c = 0
		if (random.random() > .5):
			c = chr(random.randint(65,90))
		else:
			c = chr(random.randint(97, 122))

		repl += c

	str_repl[s] = repl

	return repl

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


def buildDirTree(dir):
	mod_dir = f"{dir}_obfuscated"

	mtd = mod_dir

	dirTree = next(os.walk(dir))[0]
	slashes = dirTree.count('/') + dirTree.count('\\')

	dirTree = []

	for dirpath, dirnames, fnames in os.walk(dir):
		check = f"{dirpath}"
		
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
		if f'{dir}{slash}logscrub.py' in files:
			print(f"\nERROR: You cannot perform a fedwalk on a directory containing itself\n\nexiting...\n")
			sys.exit()
	
	return files


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
		   "-g": "Use this option if you are inputting a group of logs. Usage: py logscrub.py -g log1.log,log2.log3.log... <options",\
		   "-d": "Same as -g, but specifying a whole directory. Usage: py logscrub.py -d [path] <options>",\
		   "-sPIP": "Scrub private IPs. Assumes /16 subnet",\
		   "-pi":"preserve all ip addresses",\
		   "-pv":"preserve vdom names",\
		   "-pd":"preserve device names",\
		   "-map=<mapfilename>":"Import IP/MAC/String mappings from other FFI program output"}

def mainLoop(args: list):

	if (len(args) < 2):
		print("Usage: \n\tpy logscrub.py logfile.log [options]\nOR\n\tpy logscrub.py -g log1.log,log2.log,... [options]\nOR\n\tpy logscrub.py -d <directory> [options]")
		sys.exit()

	if ('-h' in args[1]):
		for k,v in options.items():
			print(f'\t{k}: {v}')
		sys.exit()

	if ("-g" == args[1]):
		# Expects literally: py logscrub.py -g log1.log,log2.log,log3.log...
		og_filenames = [arg for arg in args[2].split(',')]
		if (len(args) > 2):
			for x in args[3:]:
				opflags.append(x)
	elif ("-d" == args[1]):
		dt = buildDirTree(args[2])
		mod_dir = dt[0]
		dirtree = dt[1]
		og_filenames = getFiles(dirtree)
		for x in args[3:]:
			opflags.append(x)
	else:
		og_filenames.append(args[1])
		if (len(args) > 2):
			for x in args[2:]:
				opflags.append(x)
				if ("map=" in x):
					try:
						fn = x.split('=')[1]
						importMap(fn)
					except FileNotFoundError as e:
						print(f"Could not find file/path specified: '{fn}'")
					except IndexError:
						print("-map option needs to be formatted like so:\n\t-map=<filename>")
					except:
						print("Something went wrong when importing mapfile (-map=<file> option)")


	# Load contents
	for filename in og_filenames:
		with open(filename, 'r') as logfile:
			lines = logfile.readlines()
			logentry = {}
			logfile_per_list = []
			for l in lines:
				elements = syslogregex.findall(l)
				print(elements)
				for n, e in enumerate(elements):
					logentry[e[0]] = e[1]

				logfile_per_list.append(logentry.copy())
				logentry.clear()

			logcontents.append(logfile_per_list.copy())
			logfile_per_list.clear()

	# print(logcontents)

	# Walk through contents & scrub
	for l_off, logfile in enumerate(logcontents):
		for entry_off, logentry in enumerate(logfile):
			try:
				# usernames
				if ("user" in logentry.keys()):
					if (logentry['user'] not in str_repl.keys()):
						u = logentry['user']
						str_repl[u] = logentry["user"] = f'"{replace_str(u)}"'
					else:
						logentry["user"] = str_repl[logentry['user']]

				# ip addresses (also under"ui" & msg)
				if ("srcip" in logentry.keys()):
					if (':' in logentry["srcip"]):
						if ("\"" in logentry['srcip']):
							logentry["srcip"] = f'"{replace_ip6(logentry["srcip"][1:-1])}"'
						else:
							logentry["srcip"] = replace_ip6(logentry["srcip"])
					else:
						if ("\"" in logentry['srcip']):
							logentry["srcip"] = f'"{replace_ip4(logentry["srcip"][1:-1])}"'
						else:
							logentry["srcip"] = replace_ip4(logentry["srcip"])

				if ("dstip" in logentry.keys()):
					if (':' in logentry["dstip"]):
						if ("\"" in logentry['dstip']):
							logentry["dstip"] = f'"{replace_ip6(logentry["dstip"][1:-1])}"'
						else:
							logentry["dstip"] = replace_ip6(logentry["dstip"])
					else:
						if ("\"" in logentry['dstip']):
							logentry["dstip"] = f'"{replace_ip4(logentry["dstip"][1:-1])}"'
						else:
							logentry["dstip"] = replace_ip4(logentry["dstip"])

				if ("ui" in logentry.keys()):
					ip_search = ip4.search(logentry['ui'])
					if (ip_search is None):
						ip_search = ip6.search(logentry['ui'])
					if (ip_search is not None):
						logentry['ui'] = logentry['ui'][:ip_search.span()[0]] + replace_ip4(ip_search.group()) + logentry['ui'][ip_search.span()[1]:]
				# msg
				if ("msg" in logentry.keys()):
					ip_search = ip4.search(logentry['msg'])
					if (ip_search is None):
						ip_search = ip6.search(logentry['msg'])
					if (ip_search is not None):
						logentry['msg'] = logentry['msg'][:ip_search.span()[0]] + replace_ip4(ip_search.group()) + logentry['msg'][ip_search.span()[1]:]

					for og_name, rep_name in str_repl.items():
						m = re.search(og_name, logentry['msg'])
						if (m is not None):
							logentry['msg'] = logentry['msg'][:m.span()[0]] + rep_name[1:-1] + logentry['msg'][m.span()[1]:]
				
				# device names
				if ('-pd' not in opflags and "devname" in logentry.keys()):
					if (logentry['devname'] not in str_repl.keys()):
						d = logentry['devname']
						str_repl[d] = logentry['devname'] = f'"US_FED_DEV_{replace_str(d)}"'
					else:
						logentry['devname'] = str_repl[logentry['devname']]

				# vdom names
				if ('-pv' not in opflags and "vd" in logentry.keys()):
					if (logentry['vd'] != "root" ):
						if (logentry['vd'] not in str_repl.keys()):
							v = logentry['vd']
							str_repl[v] = logentry['vd'] = f'"US_FED_VDOM_{replace_str(v)}"'
						else:
							logentry['vd'] = str_repl[logentry['vd']]
				# CSF names
			
			except (KeyError, IndexError) as e:
				print("Incomplete log")
				print(f'{e}\n{logfile}\n{logentry}')

			logfile[entry_off] = logentry.copy()
		logcontents[l_off] = logfile.copy()

	# Write modifications to scrubbed files

	if "-d" == args[1]:
		for f in og_filenames:
			a = re.search(args[2], f)
			mod_filenames.append(f[:a.span()[0]] + mod_dir + f[a.span()[1]:])

	for c, fn in enumerate(mod_filenames):
		with open(fn, 'w') as modfile:
			for d in logcontents[c]:
				for b, a in d.items():
					modfile.write(f"{b}={a} ")
				modfile.write("\n")

	repl_dicts_to_logfile("log_mappedcontents.txt")