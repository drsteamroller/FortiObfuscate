# fortiobfuscate.py - Bringing it all together
# Author - Andrew McConnell
# Date - 05/25/2023

import sys
import os
import tkinter as tk

try:
    import tools.confsrb as conf
    import tools.fedwalk as fedwalk
    import tools.logscrub as log
    import tools.pcapsrb as pcap
except ImportError:
    print("You must download the entire package from GitHub")
    sys.exit()

# First, either:
# Set up GUI
main_window = tk.Tk()
main_window.geometry("900x600")
main_window.title("FortiObfuscate")

label = tk.Label(main_window, text="FortiObfuscate - scrub syslog/config/pcap files and many more files", font=("San Francisco", 20))
label.pack(anchor='w')

main_window.mainloop()
# Take in directory

# Build target directory for modified files in the backend
# Beautify directory output onto GUI
# Buttons or drop-down menu to specify one of the 'specialty' tools: (logscrub, pcapsrb, confsrb)
# Every program that is not specified will be fed to fedwalk

# Throw all output into the target directory