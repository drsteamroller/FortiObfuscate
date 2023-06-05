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

IP_REPL_MSTR = dict()
MAC_REPL_MSTR = dict()
STR_REPL_MSTR = dict()
og_workspace = ""
mod_workspace = ""
opflags = []

# list of lists containing 2 items -> [file_path, combobox]
fp_combox_mapping = []

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

# Button Function
def obf_on_submit():
    for [path, combo] in fp_combox_mapping:
        print(f"File_Path = {path}\nComboBox Option = {combo.get()}")

options = {"-pi, --preserve-ips":"Program scrambles routable IP(v4&6) addresses by default, use this option to preserve original IP addresses",\
		   "-pm, --preserve-macs":"Disable MAC address scramble",\
		   "-ps, --preserve-strings":"Disable sensitive string scramble",\
			"-sPIP, --scramble-priv-ips":"Scramble private/non-routable IP addresses",\
			"-sp, --scrub-payload":"Sanitize payload in packet (DHCP/TFTP supported, HTTP under construction)",\
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
            opflags.append(a)

# First, either:
# Set up GUI
main_window = tk.Tk()
main_window.geometry("1000x750")
main_window.title("FortiObfuscate")

label = tk.Label(main_window, text="FortiObfuscate - scrub syslog/config/pcap files and much more", font=("San Francisco", 20))
label.grid(column=0, row=0)

m_frame = tk.Frame(main_window, padx=75, pady=75, bg='black', bd=1, relief="raised")
m_frame.grid(column=0, row=1)

treeframe = tk.Frame(m_frame, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
treeframe.grid(column=0, row=0)

comboframe = tk.Frame(m_frame, padx=5, pady=5, bg="dark grey", bd=1, relief="sunken")
comboframe.grid(column=1, row=0)

help = ttk.Button(main_window, command=None, text="Help")
help.grid(column=0, row=2)

submit = ttk.Button(main_window, command=obf_on_submit, text="Submit")
submit.grid(column=0, row=3)

# variable list of comboboxes based on the output of os.walk
print(og_workspace)
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

# Build target directory for modified files in the backend
# Beautify directory output onto GUI
# Buttons or drop-down menu to specify one of the 'specialty' tools: (logscrub, pcapsrb, confsrb)
# Every program that is not specified will be fed to fedwalk

# Throw all output into the target directory