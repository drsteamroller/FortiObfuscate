# FortiObfuscate

Fortinet Federal Tool to utilize consistent replacement across multiple different files (and file types). 

## Dependencies

dpkt, binaryornot

```
pip install dpkt binaryornot
```

## Usage

Usage examples to come soon.

To run the program, you simply need to run it with a directory as its only argument:

```
py fortiobfuscate.py <directory> [optional options]
```

All options, save for --preserve-macs (-pm) are available on the GUI. A "Help" button is also available on the GUI to explain each option, plus more.

## Why aren't all sensitive values getting scrubbed?

This is best explained with what each menu option does

config, syslog, pcap: These sub-programs depend on standardized context to grab (specifically) string values. Fields in syslog-formatted files can include user=<username>, devid=1234, etc. This makes the string values easier to grab and replace

fedwalk: this program specifically only looks for ip address patterns, and will replace any strings that have been cached by the previously mentioned programs. If you are only using 'fedwalk' on all your files, it will not replace any sensitive string values.


@TODO
- ID and fix PCAP byte conversion when strings are found before pcap scrubbing