# ----- License -------------------------------------------------- # 

#  IPScan - IPScan is a Python tool for discovering active hosts on a network using fast, multithreaded ping sweeps.
#  Copyright (c) 2025 - CursedSec (Operated by Cursed271). All rights reserved.

#  This software is an proprietary intellectual property developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the CURSEDSEC OWNERSHIP EDICT:
#
#  🚫 PROHIBITION WARNING 🚫
#  Redistribution, re-uploading, and unauthorized modification are strictly forbidden 
#  under the COE. Use is granted ONLY under the limited terms defined in the official 
#  LICENSE file (COE), which must be included in all copies.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 LICENSE: CURSEDSEC OWNERSHIP EDICT (COE)
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import os
import ipaddress
import subprocess
import concurrent.futures
from rich.console import Console

# ----- Global Declaration --------------------------------------- #

console = Console()

# ----- Scanning Function ---------------------------------------- #

def host_alive(ip):
	cmd = ["ping", "-n", "1", ip] if os.name == "nt" else ["ping", "-c", "1", ip]
	result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return ip if result.returncode == 0 else None

# ----- Validate IP Address -------------------------------------- #

def validation(subnet):
	try:
		network = ipaddress.ip_network(subnet, strict=False)
	except ValueError:
		console.print(rf"[red][!] Invalid Subnet Range! Example: 192.168.1.0/24")
		return
	live_hosts = []
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		results = executor.map(host_alive, [str(ip) for ip in network.hosts()])
	for result in results:
		if result:
			live_hosts.append(result)
			console.print(rf"[green][+] IP Address - {result} is active")
	console.print(rf"[#C6ECE3][+] Port Scanning is Completed! We found {len(live_hosts)} to be active.")

# ----- Banner --------------------------------------------------- #

def ascii():
	console.print(rf"""[#C6ECE3]
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│    ooooo ooooooooo.    .oooooo..o                                    │  
│    `888' `888   `Y88. d8P'    `Y8                                    │  
│     888   888   .d88' Y88bo.       .ooooo.   .oooo.   ooo. .oo.      │  
│     888   888ooo88P'   `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b     │  
│     888   888              `"Y88b 888        .oP"888   888   888     │  
│     888   888         oo     .d8P 888   .o8 d8(  888   888   888     │  
│    o888o o888o        8""88888P'  `Y8bod8P' `Y888""8o o888o o888o    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
	""")
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")
	console.print(rf"[#C6ECE3]  IPScan - Fast. Focused. No-Nonsense Network Sweeping.")
	console.print(rf"[#C6ECE3]  Created by [bold black]Cursed271")
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
	os.system("cls" if os.name == "nt" else "clear")
	ascii()
	subnet = console.input("[#C6ECE3][?] Enter the IP Range to perform Active Host Discovery:  ")
	validation(subnet)
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")

# ----- End ------------------------------------------------------ #
