#!/usr/bin/env python3
# Author: Andrew McConnell
# Date: 03/15/2023

import re
import random
import sys
import os

# Global Variables
contents = []
og_filenames = 0
str_repl = dict()
ip_repl = dict()
opflags = []
mod_dir = ""

#REGEX ----> Use "group" function to select the part that matches https://docs.python.org/3/library/re.html#match-objects
ipaddr4 = r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ipaddr6 = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

# Helper Functions
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

# a more granular check
def isValidIP6(addr):
    if type(addr) == bytes:
        addr = str(addr)[2:-1]
    
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

# Replaces IP addresses
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

    if not isValidIP6(ip):
         return ip

    if ip not in ip_repl.keys() and "-pi" not in opflags:
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

# Troubleshooting command to show the contents of what was loaded
def show():
    print(contents)

# Exports file that was loaded (pre or post obfuscation)
def export(args):
    new_filename = ""
    modfilenames = []
    for fn in og_filenames:
        new_filename = fn.replace(".conf", "_mod.conf")
        if('-d' in args):
            a = re.search(args[2], fn).span()
            modfilenames.append(fn[:a[0]] + mod_dir + fn[a[1]:])
        else:
            modfilenames.append(new_filename)
    
    for index, w_file in enumerate(modfilenames):
        with open(w_file, 'w') as write:
            for line in contents[index]:
                write.write(line)

def showMap(op):
    if (not ip_repl):
        print("\nYou haven't obfuscated a configuration file yet\n")
        return

    ipv4s = "\t===>>> IPv4 ADDRESSES <<<===\nOriginal -> Replacement\n"
    ipv6s = "\t===>>> IPv6 ADDRESSES <<<===\nOriginal -> Replacement\n"
    
    for k, v in ip_repl.items():
        if len(v) > 15:
            ipv6s += f"{k} -> {v}\n"
        else:
            ipv4s += f"{k} -> {v}\n"
    sep = '=' * 50

    if (op == "p"):
        print(f"{ipv4s}\n{sep}\n{ipv6s}")
        return
    elif (op == "w"):
        with open(f"config_mapping.txt", 'w') as vi:
            vi.write("+---------- MAPPED IP ADDRESSES ----------+\n")
            for og, rep in ip_repl.items():
                vi.write(f"Original IP: {og}\nMapped IP: {rep}\n\n")
            vi.write("+---------- MAPPED MAC ADDRESSES ---------+\n\n")

            vi.write("+---------- MAPPED STRING VALUES ---------+\n")
            for og, rep in str_repl.items():
                vi.write(f"Original String: {og}\nMapped String: {rep}\n\n")
        print(f"\nMap file written to {og_filenames}_ipmapping.txt\n")
    else:
        print("\nUnknown option\n")

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
        if f'{dir}{slash}confsrb.py' in files:
            print(f"\nERROR: You cannot perform a confsrb on a directory containing itself\n\nexiting...\n")
            sys.exit()
    
    return files

# Obfuscation main fuction
def obfuscate(conf):

    # If no file loaded, prompt to load a file
    if (not conf):
        return("\nEmpty\n")

    ## FOR LOOP EXT VARS ##
    # Compile the regex found at the top of this program
    is_ip4 = re.compile(ipaddr4)
    is_ip6 = re.compile(ipaddr6, re.MULTILINE)

    # Flags to look for "edit <name>" within snmp/vpn config
    SNMP = False
    SNMP_HOSTS = False
    IPSEC_P1 = False
    IPSEC_P2 = False

    # Handle naming of snmp and vpn replacement names

    # Debugging
    x = ""

    # Parse through the list containing the lines of the configuration file
    for i, content in enumerate(conf):

        # Record the number of leading spaces, so we aren't having awkward lines that aren't in-line
        leading = " " * re.search('\S', content).start()
        
        # If we see 'set hostname' or 'set alias', replace those with 'US Federal Customer'
        if ("set hostname" in content or "set alias" in content or "description" in content):
            l = content.strip().split(" ")
            name = replace_str(l[2])
            l[2] = f"US_Fed_Cx_{name}\n"
            content = leading + "{} {} {}".format(l[0], l[1], l[2])
        
        # If we see an IP address, check if it's public, and if so, replace it
        if (is_ip4.search(content)):
            a = is_ip4.search(content).span()
            g = content.strip().split(" ")
            if (len(g) == 3):
                if ('"' in g[2]):
                    g[2] = g[2][1:-1]

                g[2] = content[:a[0]] + replace_ip4(content[a[0]:a[1]]) + content[a[1]:]
                    
            elif (len(g) > 3):
                for b, ip in enumerate(g[2:]):
                    g[b + 2] = replace_ip4(ip)

            leading += " ".join(g)
            content = leading + "\n"

        elif (is_ip6.search(content)):
            g = content.strip().split(" ")
            if (len(g) == 3):
                if ('"' in g[2]):
                    g[2] = g[2][1:-1]
                if ('/' in g[2]):
                    g[2] = replace_ip6(g[2].split('/')[0]) + g[2].split('/')[1]
                else:
                    g[2] = replace_ip6(g[2])
            elif (len(g) > 3):
                for b, ip in enumerate(g):
                    g[b + 2] = replace_ip6(ip)

            leading += " ".join(g)
            content = leading + "\n"
        
        ### SNMP Communities ###
        if ("-ps" not in opflags):
            if ("config system snmp community" in content or "config system snmp user" in content):
                SNMP = True
            
            if (not SNMP_HOSTS and SNMP and "edit" in content):
                s = content.strip().split(" ")
                if (len(g) > 1):
                    name = s[1]
                    s[1] = f'fed_snmp_comm_{replace_str(name)}'
                
                leading += " ".join(s)
                content = leading + "\n"

            if (SNMP and "config hosts" in content):
                SNMP_HOSTS = True

            if (SNMP_HOSTS and "edit" in content):
                s = content.strip().split(" ")
                if (len(g) > 1):
                    name = s[1]
                    s[1] = f'fed_snmp_comm_{replace_str(name)}'

                leading += " ".join(s)
                content = leading + "\n"

            if (SNMP and "name" in content):
                s = content.strip().split(" ")
                leading += f'{s[0]} {s[1]} FED_SNMP_Community\n'
                content = leading

            if (SNMP_HOSTS and "end" in content):
                SNMP_HOSTS = False
            
            if (not SNMP_HOSTS and SNMP and "end" in content):
                SNMP = False
        
        ### VPN Tunnel Names ###
        if ("-pv" not in opflags):
            if ("config vpn ipsec phase1-interface" in content):
                IPSEC_P1 = True

            if ("config vpn ipsec phase2-interface" in content):
                IPSEC_P2 = True

            if (IPSEC_P1 and "set remotegw-ddns" in content):
                v = content.strip().split(" ")
                
                repl = f'{replace_str(v[2])}.net'
                
                leading += f'{v[0]} {v[1]} {repl}\n'
                content = leading

            if (IPSEC_P1 and "edit" in content):
                v = content.strip().split(" ")
                repl = f'vpn_p1_{replace_str(v[1])}'

                leading += f"{v[0]} {repl}\n"
                content = leading
                
            if (IPSEC_P2 and "edit" in content):
                v = content.strip().split(" ")
                repl = f'vpn_p2_{replace_str(v[1])}'

                leading += f"{v[0]} {repl}\n"
                content = leading
            
            if (IPSEC_P2 and "set phase1name" in content):
                v = content.strip().split(" ")
                repl = replace_str(v[2])
                
                leading += f"{v[0]} {v[1]} {repl}\n"
                content = leading

            if (IPSEC_P1 and "end" in content):
                IPSEC_P1 = False

            if (IPSEC_P2 and "end" in content):
                IPSEC_P2 = False

        conf[i] = content

    return conf

options = {"-h": "Display this output",\
           "-g": "Use this option if you are inputting a group of logs. Usage: py logscrub.py -g log1.log,log2.log3.log... <options>",\
           "-d": "Same as -g, but specifying a whole directory. Usage: py logscrub.py -d [path] <options>",\
           "-sPIP": "Scrub private IPs. Assumes /16 subnet",\
           "-pi":"preserve all ip addresses",\
           "-ps":"preserve snmp community names",\
           "-pv":"preserve vpn phase1/2 names names",\
           "-map=<mapfilename>":"Import IP/MAC/String mappings from other FFI program output"}

def mainLoop(args: list):

    if len(args) < 2:
        print("Usage:\n\tpython confsrb.py <config file> [options] OR\
                    \n\tpython confsrb.py -g conf1,conf2,... [options] OR\
                    \n\tpython confsrb.py -d <dir> [options]\n")
        sys.exit()

    if args[1] == '-g':
        if len(args) < 3:
            print("Usage:\n\tpython confsrb.py -g conf1,conf2,... [options]\n")
            sys.exit()
        try:
            og_filenames = [fn for fn in args[2].split(',')]
            for file in og_filenames:
                with open(file, 'r') as f:
                    contents.append(f.readlines())        
        except IndexError:
            print("Usage:\n\tpython confsrb.py -g conf1,conf2,... [options]\n")
            sys.exit()
        except FileNotFoundError:
            print("Couldn't find one of the files provided")
            sys.exit()
        if len(args) > 3:
            for x in args[3:]:
                if "-map" in x:
                    mapfn = x.split('=')[1]
                    try:
                        importMap(mapfn)
                    except:
                        print(f"Could not read map file: {mapfn}")
                else:
                    opflags.append(x)


    elif args[1] == '-d':
        if len(args) < 3:
            print("\n\tpython confsrb.py -d <dir> [options]\n")
            sys.exit()
        if os.path.isfile(args[2]):
            print(f"Path provided: {args[2]} is a file, not a directory (or does not exist)")
            sys.exit()
        
        print(args[2])
        dt = buildDirTree(args[2])
        mod_dir = dt[0]
        dirtree = dt[1]
        og_filenames = getFiles(dirtree)

        curfile = ""
        try:
            for file in og_filenames:
                curfile = file
                with open(file, 'r') as f:
                    contents.append(f.readlines())
        except:
            print(f"Could not find file {curfile}")
            sys.exit()

        if len(args) > 3:
            for x in args[3:]:
                if "-map" in x:
                    mapfn = x.split('=')[1]
                    try:
                        importMap(mapfn)
                    except:
                        print(f"Could not read map file: {mapfn}")
                else:
                    opflags.append(x)

    else:
        try:
            with open(args[1], 'r') as f:
                contents.append(f.readlines())
        except:
            print(f"Could not find file {args[1]}")
            sys.exit()

    obfuscated_contents = []

    for conf_file in contents:
        obfuscated_contents.append(obfuscate(conf_file))

    export(args)