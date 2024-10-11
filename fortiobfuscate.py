# fortiobfuscate.py - Bringing it all together
# Author - Andrew McConnell
# Date - 05/25/2023

import sys
import os
import re
from binascii import hexlify, unhexlify
import tkinter as tk
import tkinter.ttk as ttk

try:
    import tools.confsrb as conf
    import tools.fedwalk as fedwalk
    import tools.logscrub as log
    import tools.pcap_scrub as pcap
except ImportError as e:
    print(f"You must download the entire package from GitHub, and download all dependencies:\n {e}")
    sys.exit(2)

### Disclaimer ###

ack = input("\
You are about to run the FortiObfuscate scrubbing script. This script does not scrub every sensitive value 100 percent of the time\n\
Always perform a manual review before submitting any material to any person(s) outside of Fortinet Federal, Inc.\n\
Type 'I acknowledge' to proceed\n\
>>>  ")

if not('I acknowledge' in ack):
    sys.exit(1)

ip_repl_mstr = {}
mac_repl_mstr = {}
str_repl_mstr = {}
og_workspace = ""
mod_workspace = ""
opflags = []
agg_fedwalk = False
debug_mode = False

# list of lists containing 2 items -> [file_path, combobox]
fp_combox_mapping = []

def importMap(filename):
    """
    Import mapping to populate str/ip/mac_repl_mstr dictionaries (usually from a previous run of this program)\\
    Params: 
    filename : str of filename, which is opened and read by the function
    """
    lines = []
    with open(filename, 'r') as o:
        lines = o.readlines()

    imp_ip = False
    imp_mac = False
    imp_str = False

    for l in lines:
        if '>>>' in l:
            if 'IP' in l:
                imp_ip = True
                imp_mac = False
                imp_str = False
            elif 'MAC' in l:
                imp_ip = False
                imp_mac = True
                imp_str = False
            elif 'Strings' in l:
                imp_ip = False
                imp_mac = False
                imp_str = True
            else:
                print("Map file is improperly formatted, do not make changes to the map file unless you know what you are doing")
                sys.exit(3)
            continue
        
        # Skip this line if it is empty
        if not len(l):
            continue

        if imp_ip:
            components = l.split(' -> ')
            try:
                ip_repl_mstr[components[0]] = components[1]
            except:
                print(f"\nImproperly formatted line (or newline): {l}\n")
        elif imp_mac:
            components = l.split(' -> ')
            try:
                mac_repl_mstr[components[0]] = components[1]
            except:
                print(f"\nImproperly formatted line (or newline): {l}\n")
        elif imp_str:
            components = l.split(' -> ')
            try:
                str_repl_mstr[components[0]] = components[1]
            except:
                print(f"\nImproperly formatted line (or newline): {l}\n")
        
        else:
            print("Something went wrong, mappings might not be fully imported\n")
            print(f"Interpreted mappings based on import\n\
                  IP Mapping: {ip_repl_mstr}\n\
                  MAC Address Mapping: {mac_repl_mstr}\n\
                  String Mapping: {str_repl_mstr}\n")
    
    # Finally, we merge these imports with the subroutine replacement dictionaries
    set_repl_dicts()


def buildDirTree(dir):
    """
    Stages a target directory and gives us a clean pointer to the top level dir for the next function\\
    Params:
    dir : string of the TLD, which is parsed by os.walk
    """
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
    """
    Takes the dirTree list of the buildDirTree function and siphons out the files, which we will then use to obfuscate\\
    Params:
    dirTree: os.walk list of directories and files in the top level directory supplied

    Returns:
    list of files in all directories inside the TLD including the top level directory
    """
    slash = '/'

    files = []
    # Gotta love Windows
    if sys.platform == 'win32':
        slash = '\\'
    
    # list comprehension ftw! dir + slash (/ or \) + filename
    for dir in dirTree:
        try:
            files.extend([f'{dir}{slash}{i}' for i in next(os.walk(dir))[2]])
            if f'{dir}{slash}{args[0]}' in files:
                print(f"\nERROR: You cannot perform fortiobfuscate on a directory containing itself\n\nexiting...\n")
                sys.exit(4)
        except TypeError as e:
            print(f"Encountered {e} at directory {dir}")
    
    return files

def abbrevIP6(ip6):
    # FULL quartet (ffff, abcd, ad0c, f001) -> do nothing
    # LEADING ZEROES (00ff, 0f01, 0001) -> chop them off
    # ALL ZEROES -> kill all and adjacent all zero quartets and replace with ::
    reconst = ""
    addColon = True
    for quartet in ip6.split(':'):
        if quartet == '0000':
            if addColon:
                reconst += ":"
                addColon = False
            continue

        zero = True
        re = ''
        for hex in quartet:
            if hex != '0':
                zero = False
            
            if not zero:
                re += hex
        quartet = re

        reconst += quartet + ':'
    
    return reconst[:-1]

# Button Functions
def help():
    """
    Creates the Help window when the Help button is pressed
    """
    message_txt = "Explanation of the menu items:\n\
        'config' = select this if the associated file is a Fortinet configuration file\n\
        'syslog' = select this if the associated file is a syslog file (best if directly from FortiAnalyzer)\n\
        'pcap' = select this if the file is a pcap file\n\
        'fedwalk' = select this if the file is not best classified by the above options\n\
        'exempt' = select this if you explicitly do not want to scrub this file\n\n\
Option Buttons:\n\
        'Preserve IPs' = Do not perform scrubbing of IPs\n\
        'Preserve Strings' = Do not perform scrubbing of strings (usernames, device names, etc)\n\
        'Scrub PCAP Payloads' = Scrubs the upper layer protocol payloads (some, not all)\n\
        'Scrub Private IPs' = Replaces RFC-1918 IP addresses with a randomize /16 address\n\
        'Aggressive Replacement' = Enables fedwalk to do a second runthrough of all 'conf', 'syslog', and 'pcap' selected files\n\
        'Scrub Edit Lines' = Scrub each and every line containing the 'edit' prefix\n\n\
The Submit button will perform the associated obfuscation operations on the files listed based on the selection and\n\
with respect to the arguments chosen\n\n\
To turn on Debug (detailed logs) mode: press <F12> when on the main screen of the program"

    helpPopupWin = tk.Tk()
    helpPopupWin.geometry("800x350")
    helpPopupWin.title("GUI - Help")

    helpBanner = ttk.Label(helpPopupWin, text="How to use FortiObfuscate", font=("San Francisco", 18))
    helpBanner.grid(column=0, row=0)

    message = ttk.Label(helpPopupWin, text = message_txt, font=("San Francisco", 12))
    message.grid(column=0, row=1)

    helpPopupWin.mainloop()

def update_opflags(txt : str):
    """
    Add or remove certain options based on buttons pressed on the GUI
    """
    if "Preserve IP" in txt:
        if '-pi' in opflags:
            opflags.remove('-pi')
        else:
            opflags.append('-pi')
    elif "Preserve Strings" in txt:
        if '-ps' in opflags:
            opflags.remove('-ps')
        else:
            opflags.append('-ps')
    elif "Scrub PCAP Payloads" in txt:
        if '-sp' in opflags:
            opflags.remove('-sp')
        else:
            opflags.append('-sp')
    elif "Scrub Private IPs" in txt:
        if '-sPIP' in opflags:
            opflags.remove('-sPIP')
        else:
            opflags.append('-sPIP')
    elif "Aggressive Replacement" in txt:
        if '-agg' in opflags:
            opflags.remove('-agg')
        else:
            opflags.append('-agg')
    elif "Scrub Edit Lines" in txt:
        if '-el' in opflags:
            opflags.remove('-el')
        else:
            opflags.append('-el')

def update_args(button_txt : str, update_label : tk.Label):
    """
    Updates the visual list of options selected when an option button is pressed
    """
    label_txt = update_label['text']
    bt = f"\n{button_txt}"

    if bt in label_txt:
        label_txt = label_txt.replace(bt, "")
        
    else:
        label_txt += f"\n{button_txt}"
    
    update_opflags(button_txt)
    update_label['text'] = label_txt

    print(opflags)

def allof(all : ttk.Combobox, allcbx : list[str, ttk.Combobox]):
    """
    Function of the 'All: ' button, sets all comboboxes to chosen option
    """
    option = all.get()

    for [path, combox] in allcbx:
        combox.set(option)

# For when a map is imported
def set_repl_dicts():
    """
    Set the individual program replacement dictionaries to the master dictionaries
    """

    global ip_repl_mstr
    global mac_repl_mstr
    global str_repl_mstr

    log.ip_repl     |= ip_repl_mstr
    conf.ip_repl    |= ip_repl_mstr
    fedwalk.ip_repl |= ip_repl_mstr
    pcap.ipswap     |= ip_repl_mstr

    log.str_repl     |= str_repl_mstr
    conf.str_repl    |= str_repl_mstr
    fedwalk.str_repl |= str_repl_mstr
    pcap.strswap     |= str_repl_mstr

    fedwalk.mac_repl |= mac_repl_mstr


# Grabs the replacement dicts from the sub-programs and appends them to the mstr dicts
def append_mstr_dicts():
    """
    Append new findings to our master dictionaries from the individual program dictionaries\\
    This is done after the obfuscation function is performed on a file
    """

    global ip_repl_mstr
    global mac_repl_mstr
    global str_repl_mstr

    if log.ip_repl:
        ip_repl_mstr = ip_repl_mstr | log.ip_repl
    if conf.ip_repl:
        ip_repl_mstr = ip_repl_mstr | conf.ip_repl
    if fedwalk.ip_repl:
        ip_repl_mstr = ip_repl_mstr | fedwalk.ip_repl
    if log.str_repl:
        str_repl_mstr = str_repl_mstr | log.str_repl
    if conf.str_repl:
        str_repl_mstr = str_repl_mstr | conf.str_repl
    if fedwalk.str_repl:
        str_repl_mstr = str_repl_mstr | fedwalk.str_repl
    if fedwalk.mac_repl:
        mac_repl_mstr = mac_repl_mstr | fedwalk.mac_repl

    if pcap.ipswap:
        ip_repl_mstr = ip_repl_mstr | pcap.ipswap
    if pcap.strswap:
        str_repl_mstr = str_repl_mstr | pcap.strswap

def print_mstr_dicts():

    print("IP replacement master dict")
    print(ip_repl_mstr)
    print("STR replacement master dict")
    print(str_repl_mstr)
    print("MAC replacement master dict")
    print(mac_repl_mstr)

def print_child_proc_dicts():

    print("Order is always: conf, syslog, pcap, fedwalk")
    print("IP replacement child dicts")
    print(conf.ip_repl)
    print(log.ip_repl)
    print(pcap.ipswap)
    print(fedwalk.ip_repl)
    print("STR replacement child dicts")
    print(conf.str_repl)
    print(log.str_repl)
    print(pcap.strswap)
    print(fedwalk.str_repl)

def clear_non_fedwalk_repl_dicts():

    del pcap.ipswap
    del pcap.strswap
    del conf.ip_repl
    del conf.str_repl
    del log.ip_repl
    del log.str_repl

def obf_on_submit(progress: ttk.Progressbar):
    """
    Main function of the program, takes the list of files from the TLD and walks through them,\\
    performing a corresponding obfuscation based on their mapped combobox option
    """
    debug_log = None
    global debug_mode
    global agg_fedwalk
    global ip_repl_mstr
    global mac_repl_mstr
    global str_repl_mstr

    if debug_mode:
        debug_log = open("fortiobfuscate_debug.log", 'w')
    
    if '-agg' in opflags:
        agg_fedwalk = True

    save_fedwalk_for_last = []
    aggressive_fedwalk = []
    amount_of_files = len(fp_combox_mapping)

    for num, [path, combo] in enumerate(fp_combox_mapping):
        modified_fp = path.replace(og_workspace, mod_workspace)

        if "config" in combo.get():
            conf.mainLoop(opflags, path, modified_fp, debug_log)
            if agg_fedwalk:
                aggressive_fedwalk.append(modified_fp)
                
            print(f"[CONFIG] - {path} obfuscated and written to {modified_fp}")
        elif "syslog" in combo.get():
            log.mainloop(opflags, path, modified_fp, debug_log)
            if agg_fedwalk:
                aggressive_fedwalk.append(modified_fp)
            print(f"[SYSLOG] - {path} obfuscated and written to {modified_fp}")
        elif "pcap" in combo.get():
            pcap.mainloop(opflags, path, modified_fp, debug_log)
            if agg_fedwalk:
                aggressive_fedwalk.append(modified_fp)
            print(f"[PCAP] - {path} obfuscated and written to {modified_fp}")
        elif "fedwalk" in combo.get():
            save_fedwalk_for_last.append((path, modified_fp))
        else:
            print(f"[EXEMPT] - {path} exempted and copied to {modified_fp}")

        progress['value'] = ((num+1)/amount_of_files)*100

        append_mstr_dicts()
        set_repl_dicts()

    clear_non_fedwalk_repl_dicts()

    for num, (src, dst) in enumerate(save_fedwalk_for_last):
        fedwalk.mainloop(opflags, src, dst, debug_log)
        print(f"[FEDWALK] - {src} obfuscated and written to {dst}")
    
    for src in aggressive_fedwalk:
        fedwalk.mainloop(opflags, src, src, debug_log)
        print(f"[FEDWALK] - Additional pass through on {src}, overwritten in place")
    
    map_output = ""

    map_output += "\nMaster Dictionaries:\n\n>>> IP Addresses\n"
    for k,v in ip_repl_mstr.items():
        map_output += f"{k} -> {v}\n"
    map_output += "\n>>> MAC Addresses\n"
    for k,v in mac_repl_mstr.items():
        map_output += f"{k} -> {v}\n"
    map_output += "\n>>> Strings\n"
    for k,v in str_repl_mstr.items():
        map_output += f"{k} -> {v}\n"

    with open(f"mapof_{og_workspace}.txt", 'w') as mapfile_out:
        mapfile_out.write(map_output)

    if debug_log:
        debug_log.close()
        debug_mode = False
        print("Submit Process Finished, debug mode has been turned off\n")

options = {"-pi, --preserve-ips":"Program scrambles routable IP(v4&6) addresses by default, use this option to preserve original IP addresses",\
		   "-pm, --preserve-macs":"Disable MAC address scramble",\
		   "-ps, --preserve-strings":"Disable sensitive string scramble",\
			"-sPIP, --scramble-priv-ips":"Scramble private/non-routable IP addresses",\
			"-sp, --scrub-payload":"Sanitize (some) payload in packet for pcaps",\
			"-ns":"Non-standard ports used. By default pcapsrb.py assumes standard port usage, use this option if the pcap to be scrubbed uses non-standard ports",\
			"-map=<MAPFILE>":"Take a map file output from any FFI program and input it into this program to utilize the same replacements"}

# Take in directory from the CLI
args = sys.argv

if len(args) < 2:
    print("Usage:\n\tpython fortiobfuscate.py <directory> [options]")
    sys.exit(5)

if args[1] == "-h":
    print("Options")
    for k,v in options.items():
        print(f"{k} : {v}")
    sys.exit(-1)

else:
    og_workspace = args[1]
    if len(args) > 2:
        for a in args[2:]:
            if '-map=' in a:
                importMap(a.split('=')[1])
            else:
                opflags.append(a)

# First, either:
# Set up GUI
l, w = 830, 700

main_window = tk.Tk()
main_window['bg'] = 'dark grey'
main_window.geometry(f"{l}x{w}")
main_window.title("FortiObfuscate")

combox_options = ['config', 'syslog', 'pcap', 'fedwalk', 'exempt']

label = tk.Label(main_window, text="FortiObfuscate - scrub syslog/config/pcap files and much more", font=("San Francisco", 20))
label.grid(column=0, row=0)

m_frame = tk.Frame(main_window, height=500, width=700, padx=10, pady=25, bg='black', bd=1, relief="raised")
m_frame.grid(column=0, row=1)


'''
treeframe = tk.Frame(m_frame, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
treeframe.grid(column=0, row=0)

comboframe = tk.Frame(m_frame, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
comboframe.grid(column=1, row=0)
'''

switchframe = tk.Frame(main_window, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
switchframe.grid(column=0, row=2)

argframe = tk.Frame(switchframe, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
argframe.grid(column=0, row=0)

arglabel = tk.Label(argframe, text="Arguments to pass to programs", font=("San Francisco", 12))
arglabel.pack()

buttonarr = tk.Frame(switchframe, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
buttonarr.grid(column=0, row=1)

listargs = tk.Frame(switchframe, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
listargs.grid(column=0, row=2)

cli_args = ""
for x in opflags:
    if '-pi' in x:
        cli_args += "\nPreserve IPs"
    elif '-pm' in x:
        cli_args += "\nPreserve MACs"
    elif '-ps' in x:
        cli_args += "\nPreserve Strings"
    elif '-sp' in x:
        cli_args += "\nScrub PCAP Payloads"
    elif '-sPIP' in x:
        cli_args += "\nScrub Private IPs"
    elif '-agg' in x:
        cli_args += "\nAggressive Replacement"

current_selected_args = tk.Label(listargs, text=f"Arguments selected:{cli_args}", font=("San Francisco", 12))
current_selected_args.pack()

preserveIP_button = ttk.Button(buttonarr, command=lambda : update_args("Preserve IPs", current_selected_args), text="Preserve IPs")
preserveIP_button.grid(column=0, row=0)

preserveSTR_button = ttk.Button(buttonarr, command=lambda : update_args("Preserve Strings", current_selected_args), text="Preserve Strings")
preserveSTR_button.grid(column=1, row=0)

scrubpayload_button = ttk.Button(buttonarr, command=lambda : update_args("Scrub PCAP Payloads", current_selected_args), text="Scrub PCAP payloads")
scrubpayload_button.grid(column=0, row=1)

scrubprivateIPs_button = ttk.Button(buttonarr, command=lambda : update_args("Scrub Private IPs", current_selected_args), text="Scrub Private IPs")
scrubprivateIPs_button.grid(column=1, row=1)

aggressiveReplacement_button = ttk.Button(buttonarr, command=lambda : update_args("Aggressive Replacement", current_selected_args), text="Aggressive Replacement (Experimental)")
aggressiveReplacement_button.grid(column=0, row=2)

editLines_button = ttk.Button(buttonarr, command=lambda : update_args("Scrub Edit Lines", current_selected_args), text="Scrub Edit Lines")
editLines_button.grid(column=1, row=2)

allOps = ttk.Combobox(buttonarr, values=combox_options)

allOps.grid(column=1, row=3)

help = ttk.Button(main_window, command=help, text="Help")
help.grid(column=0, row=3)

progress = ttk.Progressbar(main_window, orient='horizontal', length=500, mode='determinate')

submit = ttk.Button(main_window, command=lambda : obf_on_submit(progress), text="Submit")
submit.grid(column=0, row=4)

blankFrame = tk.Frame(main_window, padx=10, pady=20)
blankFrame.grid(column=0, row=5)
progress.grid(column=0, row=6)

# Build target directory for modified files in the backend
mod_workspace, dirtree_of_workspace = buildDirTree(og_workspace)
files = getFiles(dirtree_of_workspace)

for row, path in enumerate(files):
    inner = []

    nextFrame = tk.Frame(m_frame, height=25, width=650, padx=5, pady=3, bg="dark grey", bd=1, relief='raised')
    nextFrame.grid_propagate(0)
    nextFrame.grid(column=0, row=row)
    next_label = ttk.Label(nextFrame, justify="left", width=58, text=path)
    next_comb = ttk.Combobox(nextFrame, justify='right', width=20, values=combox_options)

    next_label.grid(column=0, row=0)
    next_comb.grid(column=1, row=0)

    inner.extend([path, next_comb])

    fp_combox_mapping.append(inner)

allButton = ttk.Button(buttonarr, text="All: ", command=lambda: allof(allOps, fp_combox_mapping))
allButton.grid(column=0, row=3)

def debugSwitch(event):
    global debug_mode
    debug_mode = not debug_mode
    print(f"Debug mode mode set: {'ON' if debug_mode else 'OFF'}")

def viewMap(event):

    print("Master Dictionaries:\n\n>>> IP Addresses")

    for k,v in ip_repl_mstr.items():
        print(f"{k} -> {v}")

    print("\n>>> MAC Addresses")
    for k,v in mac_repl_mstr.items():
        print(f"{k} -> {v}")

    print("\n>>> Strings")
    for k,v in str_repl_mstr.items():
        print(f"{k} -> {v}")
    
    print("\n")

def viewPCAPMap(event):

    print("PCAP Dictionaries (Binary Formatted):\n\n>>> IP Addresses")

    for k,v in pcap.ip_repl.items():
        print(f"{k} -> {v}")

    print("\n>>> MAC Addresses")
    for k,v in pcap.mac_repl.items():
        print(f"{k} -> {v}",end='')

    print("\n>>> Strings")
    for k,v in pcap.str_repl.items():
        print(f"{k} -> {v}", end='')
    
    print("\n")

main_window.bind("<F12>", debugSwitch)

main_window.bind("<F1>", viewMap)

main_window.bind("<F2>", viewPCAPMap)

main_window.mainloop()