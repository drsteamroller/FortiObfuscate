#!/usr/bin/env python3
#############################################################################################
#                 PCAP sanitization for Federal customers
# Usage:
#		pcap_scrub.py [file].pcap [options]
#		
# Options:
#		--help : Shows these options
#		-pm, --preserve-macs : Skips MAC address scramble
#		-pi, --preserve-ips : Skips IP address scramble
#		-sPIP, --scramble-priv-ips : Scramble RFC 1918 (private) IP addresses
#		-O=<OUTFILE> : Output file name for log file, which shows the ip/mac address mappings
#       -sp, --scrub-payload : Intellegently scrambles ARP and L4 data
#		-np, --nuke-payload : Unintelligently* scrambles all data past TCP/UDP header info [*Not protocol-aware] 
#
# Author: Andrew McConnell
# Date:   03/09/2023
#############################################################################################

# PCAP Scrubber, improved
# Using SCAPY

if __name__ == "__main__":
    pass

else:
    from scapy.all import *
    from scapy.layers.l2 import Ether
    import argparse
    import binascii
    import ipaddress
    import random
    import logging

    ### Globals
    ipswap          = {}
    strswap         = {}
    scapcap         = ""

    port_scrub      = {} # {port: UDP payload length}, mainly for TFTP

    ### Argument Parser Setup
    ap = argparse.ArgumentParser(
        prog        = "pcap_scrub.py",
        description = "Reads in a PCAP, scrubs it, and writes modifications to a new PCAP file"
    )

    ap.add_argument("filename")
    ap.add_argument("-sp", "--scrub-payload", action="store_true", help="Scrub >L3 payloads. Default only scrubs Eth\
                    src/dsts and IP src/dsts")
    ap.add_argument("-np", "--nuke_payload", action="store_true", help="Unintelligently replaces TCP/UDP payload with random data. Overrides --scrub-payload option")
    ap.add_argument("--skip_privip", action="store_true", help="Skip Private IP scrub")
    ap.add_argument("-skIP", "--skip_allip", action="store_true", help="Skip ALL IP scrub")
    ap.add_argument("-skSt", "--skip_string", action="store_true", help="Skip strings scrubbing (shouldn't\
                    be used with -sp, unless IP addresses are in >L3 payloads)")
    ap.add_argument("-m", "--mapfile", help="Output the IP address and String replacements to <file>")
    ap.add_argument('-d', action="store_true")

    args = []

    ### Helper Functions
    def isValidIp(ip: str) -> bool:
        try:
            p = ipaddress.ip_address(ip)
        except ValueError:
            return False
        
        return True

    def isNotPublic(ip: str) -> bool:
        addr = 0
        if not isValidIp(ip):
            return False

        addr = ipaddress.ip_address(ip)

        return not (addr.is_global)

    def replaceIp4(ip: ipaddress.IPv4Address | str) -> ipaddress.IPv4Address:
        if "-ps" in args:
            return ip
        if ip in ipswap.keys():
            return ipswap[ip]
        
        if isNotPublic(str(ip)) and "-sPIP" in args:
            return ip
        
        if str(ip) in "0.0.0.0" or str(ip) in "255.255.255.255":
            return ip

        if isNotPublic(str(ip)):
            last = random.randint(1, 254)
            split = str(ip).split('.')
            ipswap[ip] = ipaddress.IPv4Address(f"{'.'.join(split[:-1])}.{last}")
            return ipswap[ip]

        replacement = ""
        for h in range(4):
            replacement += f"{random.randint(1,254)}."
        replacement = replacement[:-1]

        ipswap[ip] = ipaddress.IPv4Address(replacement)
        
        return ipaddress.IPv4Address(replacement)

    def replaceIp6(ip: ipaddress.IPv6Address | str) -> ipaddress.IPv6Address:
        if "-ps" in args:
            return ip
        if ip in ipswap.keys():
            return ipswap[ip]
        
        if isNotPublic(str(ip)) and "-sPIP" in args:
            return ip

        replacement = ""
        for h in range(8):
            replacement = f"{hex(random.randrange(1, 65535))[2:]}:"
        replacement = replacement[:-1]

        ipswap[ip] = replacement
        
        return ipaddress.IPv6Address(replacement)

    def replaceStr(s: str) -> str | bytes:
        if s in strswap.keys():
            return strswap[s]

        replacement = ""

        if isinstance(s, bytes):
            replacement = b""
            hexr = binascii.hexlify(s)

            for i in range(0, len(hexr[2:-1]), 2):
                c = hex(random.randint(0, 15))[2:]
                c += hex(random.randint(0, 15))[2:]
                c = bytes(c, 'utf-8')
                replacement += c

            return binascii.unhexlify(replacement)
        else:
            for i in range(len(s)):
                if (random.random() > .5):
                    c = chr(random.randint(65,90))
                else:
                    c = chr(random.randint(97, 122))
                
                replacement += c
        
        strswap[s] = replacement
        
        return replacement

    def writeMapsToFile(filename: str) -> None:
        try:
            with open(filename, 'w') as mapfile:

                mapfile.write("<<<<<  IP Address Replacements  >>>>>\n{Original} -> {Replacement}\n\n")
                for og, rp in ipswap.items():
                    mapfile.write(f"{og} -> {rp}\n")
                mapfile.write('\n')

                mapfile.write("<<<<<  String Replacments  >>>>>\n\n")
                for og, rp in strswap.items():
                    mapfile.write(f"{og} -> {rp}\n")
                mapfile.write('\n')

            print(f"Maps outputted to {filename}\n")

        except Exception as e:
            print(f"Ran into an issue when writing maps to outfile: {e}\n")
            print(traceback.format_exc())
            print("\nNo output file written to")
        
    def nuke_payload(p: scapy.packet) -> scapy.packet:
        if p.haslayer("UDP"):
            p['UDP'].payload = replaceStr(p['UDP'].payload)
        else:
            p['TCP'].payload = replaceStr(p['TCP'].payload)
        
        return p


    def mainloop(args_: list, src_path: str, dst_path: str, debug_log: str):

        args = args_

        ### Read PCAP
        with open(src_path, 'rb') as pcap:
            scapcap = rdpcap(pcap)

        ### Parse PCAP

        for c, pkt in enumerate(scapcap):

            print(pkt)
            if pkt.haslayer('IP'):
                og_src = pkt["IP"].src
                og_dst = pkt["IP"].dst
                pkt["IP"].src = replaceIp4(pkt["IP"].src)
                pkt["IP"].dst = replaceIp4(pkt["IP"].dst)
                logging.debug(f"[PCAP] Replaced src + dst IPv4 addresses on pkt #{c+1}\n\t\
                            SRC: {og_src} -> {replaceIp4(og_src)}\n\t\
                            DST: {og_dst} -> {replaceIp4(og_dst)}")

            if pkt.haslayer('IPv6'):
                og_src = pkt["IPv6"].src
                og_dst = pkt["IPv6"].dst
                pkt["IPv6"].src = replaceIp4(pkt["IP"].src)
                pkt["IPv6"].dst = replaceIp4(pkt["IP"].dst)
                logging.debug(f"[PCAP] Replaced src + dst IPv6 addresses on pkt #{c+1}\n\t\
                            SRC: {og_src} -> {replaceIp6(og_src)}\n\t\
                            DST: {og_dst} -> {replaceIp6(og_dst)}")

            if pkt.haslayer('ARP'):
                og_src = pkt["ARP"].psrc
                og_dst = pkt["ARP"].pdst            
                pkt["ARP"].psrc = replaceIp4(pkt["ARP"].psrc)
                pkt["ARP"].pdst = replaceIp4(pkt["ARP"].pdst)
                logging.debug(f"[PCAP] Replaced ARP src + dst IPv4 addresses on pkt #{c+1}\n\t\
                            pSRC: {og_src} -> {replaceIp4(og_src)}\n\t\
                            pDST: {og_dst} -> {replaceIp4(og_dst)}")

            if pkt.haslayer('BOOTP') and '-sp' in args:
                og_rqaddr = ""
                og_srvid  = ""
                og_ciaddr = pkt["BOOTP"].ciaddr
                og_yiaddr = pkt["BOOTP"].yiaddr
                og_siaddr = pkt["BOOTP"].siaddr
                og_giaddr = pkt["BOOTP"].giaddr
                pkt["BOOTP"].ciaddr = replaceIp4(pkt["BOOTP"].ciaddr)
                pkt["BOOTP"].yiaddr = replaceIp4(pkt["BOOTP"].yiaddr)
                pkt["BOOTP"].siaddr = replaceIp4(pkt["BOOTP"].siaddr)
                pkt["BOOTP"].giaddr = replaceIp4(pkt["BOOTP"].giaddr)
                logging.debug(f"[PCAP] Replaced the following BOOTP addresses on pkt #{c+1}:\n\t\
                            Client IP address  (ciaddr): {og_ciaddr} -> {replaceIp4(og_ciaddr)}\n\t\
                            'Your' IP address  (yiaddr): {og_yiaddr} -> {replaceIp4(og_yiaddr)}\n\t\
                            Server IP address  (siaddr): {og_siaddr} -> {replaceIp4(og_siaddr)}\n\t\
                            Gateway IP address (ciaddr): {og_giaddr} -> {replaceIp4(og_giaddr)}")

                for i in range(len(pkt["DHCP"].options)):
                    if len(pkt["DHCP"].options[i]) < 2:
                        continue
                    if "end" in pkt["DHCP"].options[i]:
                        break

                    try:
                        if "server_id" in pkt["DHCP"].options[i][0]:
                            og_srvid = pkt["DHCP"].options[i][0]
                            pkt["DHCP"].options[i] = (pkt["DHCP"].options[i][0], \
                                                    replaceIp4(pkt["DHCP"].options[i][1]))
                            logging.debug(f"[PCAP] Replaced DHCP Server ID on pkt #{c+1}:\n\t\
                                        {og_srvid} -> {replaceIp4(og_srvid)}")
                        if "requested_addr" in pkt["DHCP"].options[i][0]:
                            og_rqaddr = pkt["DHCP"].options[i][0]
                            pkt["DHCP"].options[i] = (pkt["DHCP"].options[i][0], \
                                                    replaceIp4(pkt["DHCP"].options[i][1]))
                            logging.debug(f"[PCAP] Replaced DHCP Requested Address on pkt #{c+1}:\n\t\
                                        {og_rqaddr} -> {replaceIp4(og_rqaddr)}")
                            
                    except Exception as e:
                        print(f"{e} with this option:\n{pkt['DHCP'].options[i]}\n\n")


            if pkt.haslayer('TFTP') and "-sp" in args:
                if pkt.sport not in port_scrub.keys():
                    port_scrub[pkt.sport] = 0

            try:
                if pkt.dport in port_scrub.keys() and port_scrub[pkt.dport] == 0 and "-sp" in args:
                    if pkt.haslayer("TFTP_DATA"):
                        # Take length of whole UDP packet, end stream if we get a packet smaller than this
                        port_scrub[pkt.dport] = len(pkt["UDP"])
                        pkt["TFTP_DATA"].block = replaceStr(pkt["TFTP_DATA"].block)
                    else:
                        last_layer = pkt.layers()[-1]
                        port_scrub[pkt.dport] = len(pkt["Raw"].load)
                        pkt[last_layer].load = pkt[last_layer].load[:4] + replaceStr(pkt[last_layer].load[3:])

                if pkt.dport in port_scrub.keys() and port_scrub[pkt.dport] != 0 and "-sp" in args:
                    if pkt.haslayer("TFTP_DATA"):
                        pkt["TFTP_DATA"].block = replaceStr(pkt["TFTP_DATA"].block)
                    else:
                        last_layer = pkt.layers()[-1]
                        pkt[last_layer].load = pkt[last_layer].load[:4] + replaceStr(pkt[last_layer].load[3:])

                    if pkt.haslayer("UDP") and len(pkt['UDP']) < port_scrub[pkt.dport]:
                        del port_scrub[pkt.dport]
            except AttributeError:
                pass

            if "-np" in args:
                pkt = nuke_payload(pkt)
            
            ### Recalculate Checksum(s)
            del pkt.chksum
            try:
                del pkt['TCP'].chksum
            except:
                pass
            pkt = Ether(bytes(pkt))

        ### Write modifications
        wrpcap(dst_path, scapcap)