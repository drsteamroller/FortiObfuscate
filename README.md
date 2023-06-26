# FortiObfuscate

Fortinet Federal Tool to utilize consistent replacement across multiple different files (and file types). 

## Dependencies

dpkt - Interprets PCAPs in a way where we can read them, manipulate protocol header/main body values, and then write the modifications to a new pcap file
binaryornot - Simple module to check if a file is a binary file or a text file, for the fedwalk program.

```
pip install dpkt binaryornot
```

## Usage

Check the 'sample' and 'sample_obfuscated' directories in /Example.

To run the program, you simply need to run it with a directory as its only argument:

```
py fortiobfuscate.py <directory> [optional options]
```

All options, save for --preserve-macs (-pm) are available on the GUI. A "Help" button is also available on the GUI to explain each option, plus more.

Debug logging can be enabled by pressing 'F12' while on the main page of the GUI. The output file is called "fortiobfuscate_debug.log", this file will contain all actions taken by the program (including anomalies and errors). An example output is provided.

## Default Behavior

By default:

Public/routable IP addresses are scrubbed in full (A.B.C.D -> W.X.Y.Z)
User/Device names and usernames are scrubbed (see 'syslog' below, also ipsec phase1 names/ddns and snmp community names)
MAC addresses are scrubbed in full 

## Why aren't all sensitive values getting scrubbed?

This is best explained with what each menu option does

config, syslog, pcap: These sub-programs depend on standardized context to grab (specifically) string values. Fields in syslog-formatted files can include user=<username>, devid=1234, etc. This makes the string values easier to grab and replace

config: This program is written specifically for FortiGate configuration files, though it may work for other FortiProduct configuration files (though the same efficacy cannot be promised).

syslog: This program is written for syslog files (\<attribute\>=\<value\>). Some lesser used attribute values are not scrubbed, the ones that this program looks out for are: 'user', 'src/dstip', 'devname', 'vd', and 'ui'

'pcap': This program is, surprise surprise, written for pcap files. Accompanying this program, there's a 'Scrub upper layer protocols' option which will go through the data in upper level protocols and mask critical values. Check ports.txt to see a list of protocols scrubbed (minus http), and you can change the standard ports if the pcap provided utilizes different ports (use a list of values [port1, port2, ...]) if multiple non-standard ports are used between pcaps.

fedwalk: this program specifically only looks for ip address patterns, and will replace any strings that have been cached by the previously mentioned programs. If you are only using 'fedwalk' on all your files, it will not replace any sensitive string values.