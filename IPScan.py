# ----- IP Scan ---------------------------------------------------------------------------------------------------- #

# IP Scan is a ping sweeper written in python that lists all the available hosts on the network
# Created by Steven Pereira aka Cursed Cancer
# Github: https://github.com/CursedCancer

# ----- Import Section --------------------------------------------------------------------------------------------- #

import subprocess
import re
from rich.console import Console

# ----- Global Declaration ----------------------------------------------------------------------------------------- #

console = Console()

# ----- Banner Function -------------------------------------------------------------------------------------------- #

def ascii():
    console.print(r"""[#79d45e]
        ┌──────────────────────────────────────────────────────────────────────────────────────┐
        │           [#a484e9]___  ________        ________  ________  ________  ________ [#79d45e]               │ 
        │          [#a484e9]|\  \|\   __  \      |\   ____\|\   ____\|\   __  \|\   ___  \ [#79d45e]             │
        │          [#a484e9]\ \  \ \  \|\  \     \ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ [#79d45e]            │
        │           [#a484e9]\ \  \ \   ____\     \ \_____  \ \  \    \ \   __  \ \  \\ \  \ [#79d45e]           │
        │            [#a484e9]\ \  \ \  \___|      \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ [#79d45e]          │
        │             [#a484e9]\ \__\ \__\           ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ [#79d45e]         │
        │              [#a484e9]\|__|\|__|          |\_________\|_______|\|__|\|__|\|__| \|__|[#79d45e]          │
        │                                  [#a484e9]\|_________|[#79d45e]                                        │
        │                                                                                      │
        │                              [#31bff3]- WELCOME TO IPSCAN -[#79d45e]                                   │
        │      IPScan is a Ping Sweeper that lists all the available hosts on the network      │
        │                                                                                      │
        │                                      +-+-+                                           │
        │                                 [red] Cursed Cancer[#79d45e]                                       │
        │                                      +-+-+                                           │
        └──────────────────────────────────────────────────────────────────────────────────────┘
        """)

# ----- Validation Functions --------------------------------------------------------------------------------------- #

def subnet_range(ip):
    sub = ip.replace("/24", "")
    subval = sub.split(".")
    for x in subval:
        if not x.isdigit():
            console.print("You've entered the wrong Subnet Range")
            console.print("Please check your Input")
            exit()
        else:
            i = int(x)
            if i >= 0 or i <= 255:
                pass
            else:
                console.print("You've entered the wrong Subnet Range")
                console.print("Please check your Input")
                exit()

# ----- Scanning Function ------------------------------------------------------------------------------------------ #

def scanner(ip):
	subnet_range(ip)
	network = ip.replace("0/24", "")
	ip_values = []
	for host in range(1, 255):
	    ip_val = network + str(host)
	    process = subprocess.run('ping -c 1 -w 1 '+ ip_val,stdout=subprocess.PIPE, shell=True)
	    if process.returncode == 0:
	        ip_values.append(ip_val)
	        console.print(f"{ip_val} IS ALIVE!!")
	console.print("Ping completed successfully!")
	console.print(f"There are {len(ip_values)} hosts available")

# ----- Main Function ---------------------------------------------------------------------------------------------- #

if __name__ == '__main__':
	try:
		ascii()
		ip = input("Please enter a Subnet Range: ")
		scanner(ip)
	except KeyboardInterrupt:
		print("Forcefully terminated IPScan")

# ----- End -------------------------------------------------------------------------------------------------------- #