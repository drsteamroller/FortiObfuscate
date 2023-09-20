#!/usr/bin/env python3
# Description - On the way
# Author: Andrew McConnell
# Date:   04/04/2023

import random
import time
import re

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
debug_mes = ""

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
  a) expect_0 is set to True when we view a shift in 1's to 0's                                V We set it to True so if there's a '1' after a '0', it's not a net_mask
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

def salt():
    t = int( time.time() * 1000.0 )
    random.seed( ((t & 0xff000000) >> 24) +
             ((t & 0x00ff0000) >>  8) +
             ((t & 0x0000ff00) <<  8) +
             ((t & 0x000000ff) << 24))
    return random.randint(2,8)

def replace_str(s):
    if s in str_repl.keys():
        return str_repl[s]

    repl = ""
    for ch in range(len(s) + salt()):
        c = 0
        if (random.random() > .5):
            c = chr(random.randint(65,90))
        else:
            c = chr(random.randint(97, 122))

        repl += c

    str_repl[s] = repl

    return repl

def mainloop(args: list, src_path: str, dst_path: str, debug_log):

    global logcontents
    global opflags
    opflags = args
    global debug_mes

    # Load contents

    with open(src_path, 'r') as logfile:
        lines = logfile.readlines()
        logentry = {}
        logfile_per_list = []
        for l in lines:
            elements = syslogregex.findall(l)
            for n, e in enumerate(elements):
                logentry[e[0]] = e[1]

            logfile_per_list.append(logentry.copy())
            logentry.clear()

        logcontents.append(logfile_per_list.copy())
        logfile_per_list.clear()
    
    debug_mes += f"[SYSLOG] Sylog file {src_path} indexed and loaded, entering obfuscation loop\n"

    # Walk through contents & scrub
    for l_off, logfile in enumerate(logcontents):
        for entry_off, logentry in enumerate(logfile):
            try:
                # usernames
                if ("user" in logentry.keys()):
                    u = ""
                    if (logentry['user'] not in str_repl.keys()):
                        u = logentry['user']
                        str_repl[u] = logentry["user"] = f'"{replace_str(u)}"'
                    else:
                        logentry["user"] = str_repl[logentry['user']]
                    debug_mes += f"[SYSLOG] \\user\\ field identified and replaced:\n\t{u} -> {str_repl[u]}\n"

                # ip addresses (also under"ui" & msg)
                if ("srcip" in logentry.keys()):
                    replacement = ""
                    if (':' in logentry["srcip"]):
                        if ("\"" in logentry['srcip']):
                            replacement = replace_ip6(logentry["srcip"][1:-1])
                            logentry["srcip"] = f'"{replacement}"'
                        else:
                            replacement = replace_ip6(logentry["srcip"])
                            logentry["srcip"] = replacement
                        debug_mes += f"[SYSLOG] \\srcip (ipv6)\\ field identified and replaced:\n\t{logentry['srcip']} -> {replacement}\n"
                    else:
                        if ("\"" in logentry['srcip']):
                            replacement = replace_ip4(logentry["srcip"][1:-1])
                            logentry["srcip"] = f'"{replacement}"'
                        else:
                            replacement = replace_ip4(logentry['srcip'])
                            logentry["srcip"] = replacement
                        debug_mes += f"[SYSLOG] \\srcip (ipv4)\\ field identified and replaced:\n\t{logentry['srcip']} -> {replacement}\n"

                if ("dstip" in logentry.keys()):
                    replacement = ""
                    if (':' in logentry["dstip"]):
                        if ("\"" in logentry['dstip']):
                            replacement = replace_ip6(logentry["dstip"][1:-1])
                            logentry["dstip"] = f'"{replacement}"'
                        else:
                            replacement = replace_ip6(logentry["dstip"])
                            logentry["dstip"] = replacement
                        debug_mes += f"[SYSLOG] \\dstip (ipv6)\\ field identified and replaced:\n\t{logentry['dstip']} -> {replacement}\n"

                    else:
                        if ("\"" in logentry['dstip']):
                            replacement = replace_ip4(logentry["dstip"][1:-1])
                            logentry["dstip"] = f'"{replacement}"'
                        else:
                            replacement = replace_ip4(logentry["dstip"])
                            logentry["dstip"] = replacement
                        debug_mes += f"[SYSLOG] \\dstip (ipv4)\\ field identified and replaced:\n\t{logentry['dstip']} -> {replacement}\n"


                if ("ui" in logentry.keys()):
                    ip_search = ip4.search(logentry['ui'])
                    if (ip_search is None):
                        ip_search = ip6.search(logentry['ui'])
                    if (ip_search is not None):
                        logentry['ui'] = logentry['ui'][:ip_search.span()[0]] + replace_ip4(ip_search.group()) + logentry['ui'][ip_search.span()[1]:]
                        debug_mes += f"[SYSLOG] \\ui (ipv4)\\ field identified and replaced:\n\t{logentry[ip_search.span()[0]:ip_search.span()[1]]} -> {replace_ip4(ip_search.group())}\n"
                
                # msg
                if ("msg" in logentry.keys()):
                    replacement = ""
                    ip_search = ip4.search(logentry['msg'])
                    if (ip_search is None):
                        ip_search = ip6.search(logentry['msg'])
                    if (ip_search is not None):
                        logentry['msg'] = logentry['msg'][:ip_search.span()[0]] + replace_ip4(ip_search.group()) + logentry['msg'][ip_search.span()[1]:]

                    for og_name, rep_name in str_repl.items():
                        m = re.search(og_name, logentry['msg'])
                        if (m is not None):
                            logentry['msg'] = logentry['msg'][:m.span()[0]] + rep_name[1:-1] + logentry['msg'][m.span()[1]:]
                            debug_mes += f"[SYSLOG] \\critical string in msg\\ identified and replaced:\n\t{og_name} -> {rep_name}\n\tNew entry: {logentry['msg']}\n"
                
                # device names
                if ('-pd' not in opflags and "devname" in logentry.keys()):
                    replacement = ""
                    original = ""
                    if (logentry['devname'] not in str_repl.keys()):
                        original = d = logentry['devname']
                        replacement = str_repl[d] = logentry['devname'] = f'"{replace_str(d)}"'
                    else:
                        logentry['devname'] = str_repl[logentry['devname']]
                    debug_mes += f"[SYSLOG] \\devname\\ field identified and replaced:\n\t{original} -> {replacement}\n"

                # vdom names
                if ('-pv' not in opflags and "vd" in logentry.keys()):
                    replacement = ""
                    original = ""
                    if (logentry['vd'] != "root" ):
                        if (logentry['vd'] not in str_repl.keys()):
                            original = v = logentry['vd']
                            replacement = str_repl[v] = logentry['vd'] = f'"{replace_str(v)}"'
                        else:
                            logentry['vd'] = str_repl[logentry['vd']]
                    debug_mes += f"[SYSLOG] \\vd\\ field identified and replaced:\n\t{original} -> {replacement}\n"
                # CSF names
            
            except (KeyError, IndexError) as e:
                debug_mes += f"[SYSLOG] \\ERROR\\ Incomplete log file\n\nLog File:\n\t{logfile}\n\nLog Entry:\n\t{logentry}\n\n"

            logfile[entry_off] = logentry.copy()
        logcontents[l_off] = logfile.copy()

    # Write modifications to scrubbed files
    mod_filenames.append(dst_path)
    for c, fn in enumerate(mod_filenames):
        with open(fn, 'w') as modfile:
            for d in logcontents[c]:
                for b, a in d.items():
                    modfile.write(f"{b}={a} ")
                modfile.write("\n")
    
    if debug_log:
        debug_log.write(debug_mes + "\n\n")
        debug_mes = ""