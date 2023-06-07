# fortiobfuscate.py - Bringing it all together
# Author - Andrew McConnell
# Date - 05/25/2023

import sys
import os
import re
import tkinter as tk
import tkinter.ttk as ttk

try:
    import tools.confsrb as conf
    import tools.fedwalk as fedwalk
    import tools.logscrub as log
    import tools.pcapsrb as pcap
except ImportError:
    print("You must download the entire package from GitHub")
    sys.exit()

ip_repl_mstr = {}
mac_repl_mstr = {}
str_repl_mstr = {}
og_workspace = ""
mod_workspace = ""
opflags = []

# list of lists containing 2 items -> [file_path, combobox]
fp_combox_mapping = []

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
                ip_repl_mstr[OG] = components[1].strip()
                OG = ""
        elif imp_mac:
            components = l.split(':')
            if ('Original' in components[0]):
                OG = components[1].strip()
            else:
                mac_repl_mstr[OG] = components[1]
                OG = ""
        elif imp_str:
            components = l.split(':')
            if ('Original' in components[0]):
                OG = components[1].strip()
            else:
                str_repl_mstr[OG] = components[1].strip()
                OG = ""
        
        else:
            print("Something went wrong, mappings might not be fully imported\n")
            print(f"Interpreted mappings based on import\n\
                  IP Mapping: {ip_repl_mstr}\n\
                  MAC Address Mapping: {mac_repl_mstr}\n\
                  String Mapping: {str_repl_mstr}\n")


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
        try:
            files.extend([f'{dir}{slash}{i}' for i in next(os.walk(dir))[2]])
            if f'{dir}{slash}{args[0]}' in files:
                print(f"\nERROR: You cannot perform fortiobfuscate on a directory containing itself\n\nexiting...\n")
                sys.exit()
        except TypeError as e:
            print(f"Encountered {e} at directory {dir}")
    
    return files

# Button Functions
# GUI-based help output explaining what each combobox option is and what it does, and debug based help
def help():
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
        'Scrub Private IPs' = Replaces RFC-1918 IP addresses with a randomize /16 address\n\n\
The Submit button will perform the associated obfuscation operations on the files listed based on the selection and\n\
with respect to the arguments chosen"

    helpPopupWin = tk.Tk()
    helpPopupWin.geometry("800x350")
    helpPopupWin.title("GUI - Help")

    helpBanner = ttk.Label(helpPopupWin, text="How to use FortiObfuscate", font=("San Francisco", 18))
    helpBanner.grid(column=0, row=0)

    message = ttk.Label(helpPopupWin, text = message_txt, font=("San Francisco", 12))
    message.grid(column=0, row=1)

    helpPopupWin.mainloop()

def update_opflags(txt : str):
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

def update_args(button_txt : str, update_label : tk.Label):
    label_txt = update_label['text']
    bt = f"\n{button_txt}"

    if bt in label_txt:
        label_txt = label_txt.replace(bt, "")
        
    else:
        label_txt += f"\n{button_txt}"
    
    update_opflags(button_txt)
    update_label['text'] = label_txt

# For when a map is imported
def set_repl_dicts(ip_repl_mstr=ip_repl_mstr, str_repl_mstr=str_repl_mstr, mac_repl_mstr=mac_repl_mstr):
    # Be mindful that this will probably need to be converted to hex
    pcap.ip_repl = ip_repl_mstr
    log.ip_repl = ip_repl_mstr
    conf.ip_repl = ip_repl_mstr
    fedwalk.ip_repl = ip_repl_mstr

    pcap.str_repl = str_repl_mstr
    log.str_repl = str_repl_mstr
    conf.str_repl = str_repl_mstr
    fedwalk.str_repl = str_repl_mstr

    # Be mindful that this will probably need to be converted to hex
    pcap.mac_repl = mac_repl_mstr
    fedwalk.mac_repl = mac_repl_mstr

# Grabs the replacement dicts from the sub-programs and appends them to the mstr dicts
def append_mstr_dicts(ip_repl_mstr=ip_repl_mstr, str_repl_mstr=str_repl_mstr, mac_repl_mstr=mac_repl_mstr):
    # Be mindful that this will probably need to be converted to hex
    ip_repl_mstr = pcap.ip_repl | ip_repl_mstr
    ip_repl_mstr = log.ip_repl | ip_repl_mstr
    ip_repl_mstr = conf.ip_repl | ip_repl_mstr
    ip_repl_mstr = fedwalk.ip_repl | ip_repl_mstr
    str_repl_mstr = pcap.str_repl | str_repl_mstr
    str_repl_mstr = log.str_repl | str_repl_mstr
    str_repl_mstr = conf.str_repl | str_repl_mstr
    str_repl_mstr = fedwalk.str_repl | str_repl_mstr
    # Be mindful that this will probably need to be converted to hex
    mac_repl_mstr = pcap.mac_repl | mac_repl_mstr
    mac_repl_mstr = fedwalk.mac_repl | mac_repl_mstr

def obf_on_submit():

    set_repl_dicts()
    
    for [path, combo] in fp_combox_mapping:
        modified_fp = path.replace(og_workspace, mod_workspace)

        print(f"File_Path = {path}\nModified_FP = {modified_fp}\nComboBox Option = {combo.get()}")

        if "config" in combo.get():
            conf.mainLoop(opflags, path, modified_fp)
        elif "syslog" in combo.get():
            log.mainloop(opflags, path, modified_fp)
        elif "pcap" in combo.get():
            pass
        elif "fedwalk" in combo.get():
            pass
        else:
            print(f"{path} >>> exempt or blank, skipping obfuscation")
        
        append_mstr_dicts()
        set_repl_dicts()


options = {"-pi, --preserve-ips":"Program scrambles routable IP(v4&6) addresses by default, use this option to preserve original IP addresses",\
		   "-pm, --preserve-macs":"Disable MAC address scramble",\
		   "-ps, --preserve-strings":"Disable sensitive string scramble",\
			"-sPIP, --scramble-priv-ips":"Scramble private/non-routable IP addresses",\
			"-sp, --scrub-payload":"Sanitize (some) payload in packet for pcaps",\
			"-ns":"Non-standard ports used. By default pcapsrb.py assumes standard port usage, use this option if the pcap to be scrubbed uses non-standard ports. For more info on usage, run \'python pcapsrb.py -ns -h\'",\
			"-map=<MAPFILE>":"Take a map file output from any FFI program and input it into this program to utilize the same replacements"}

# Take in directory from the CLI
args = sys.argv

if len(args) < 2:
    print("Usage:\n\tpython fortiobfuscate.py <directory> [options]")
    sys.exit()

if args[1] == "-h":
    print("Options")
    for k,v in options.items():
        print(f"{k} : {v}")
    sys.exit()

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
main_window = tk.Tk()
main_window.geometry("800x750")
main_window.title("FortiObfuscate")

label = tk.Label(main_window, text="FortiObfuscate - scrub syslog/config/pcap files and much more", font=("San Francisco", 20))
label.grid(column=0, row=0)

m_frame = tk.Frame(main_window, padx=75, pady=150, bg='black', bd=1, relief="raised")
m_frame.grid(column=0, row=1)

treeframe = tk.Frame(m_frame, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
treeframe.grid(column=0, row=0)

comboframe = tk.Frame(m_frame, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
comboframe.grid(column=1, row=0)

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

current_selected_args = tk.Label(listargs, text=f"Arguments selected:{cli_args}", font=("San Francisco", 12))
current_selected_args.pack()

preserveIP_button = ttk.Button(buttonarr, command=lambda : update_args("Preserve IPs", current_selected_args), text="Preserve IPs")
preserveIP_button.grid(column=0, row=0)

preserveSTR_button = ttk.Button(buttonarr, command=lambda : update_args("Preserve Strings", current_selected_args), text="Preserve Strings")
preserveSTR_button.grid(column=1, row=0)

#preserveMAC_button (NFR)

scrubpayload_button = ttk.Button(buttonarr, command=lambda : update_args("Scrub PCAP Payloads", current_selected_args), text="Scrub PCAP payloads")
scrubpayload_button.grid(column=0, row=1)

scrubprivateIPs_button = ttk.Button(buttonarr, command=lambda : update_args("Scrub Private IPs", current_selected_args), text="Scrub Private IPs")
scrubprivateIPs_button.grid(column=1, row=1)

help = ttk.Button(main_window, command=help, text="Help")
help.grid(column=0, row=3)

submit = ttk.Button(main_window, command=obf_on_submit, text="Submit")
submit.grid(column=0, row=4)

# variable list of comboboxes based on the output of os.walk
print(og_workspace)

# Build target directory for modified files in the backend
mod_workspace, dirtree_of_workspace = buildDirTree(og_workspace)
files = getFiles(dirtree_of_workspace)

combox_options = ['config', 'syslog', 'pcap', 'fedwalk', 'exempt']

for path in files:
    inner = []

    next_label = ttk.Label(treeframe, justify="center", text=path)
    next_comb = ttk.Combobox(comboframe, justify='center', values=combox_options)
    
    next_label.pack(anchor='w')
    next_comb.pack(anchor='e')

    inner.extend([path, next_comb])

    fp_combox_mapping.append(inner)

main_window.mainloop()

# Every program that is not specified will be scrubbed with fedwalk

# Throw all output into the target directory