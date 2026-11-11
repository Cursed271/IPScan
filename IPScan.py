# ----- License -------------------------------------------------- # 

#  IPScan - IPScan discovers responsive network hosts through ICMP, ARP, and UDP probes, 
#  presenting hostnames, discovery metadata, and optional JSON assessment reports.
#  Copyright (c) 2026 - CursedSec (Operated by Cursed271). All rights reserved.

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
import re
import json
import time
import typer
import socket
import ipaddress
import subprocess
from enum import Enum
from pathlib import Path
import concurrent.futures
from rich.rule import Rule
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
from urllib.parse import urlparse
import typer.rich_utils as typer_rich
from typing import Any, Dict, List, Optional

try:
    from scapy.all import ARP, Ether, srp, IP, UDP, sr1, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ----- Global Declaration --------------------------------------- #

console = Console()
app = typer.Typer(rich_markup_mode = "rich", add_completion = False, context_settings = {"help_option_names": ["-h", "--help"]})

# ----- Host Enumeration ----------------------------------------- #

def validate_mode(value: str) -> str:
    cleaned = value.strip().lower()
    allowed = ["arp", "icmp", "udp"]
    if cleaned not in allowed:
        raise typer.BadParameter(f"IPScan Mode must be one of: {', '.join(allowed)}")
    return cleaned

def resolve_hostname(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout):
        return "Unknown"

def resolve_os(ttl: int) -> str:
    if ttl <= 0:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/Unix/macOS"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Cisco/Network Appliance"

# ----- Probe Engines -------------------------------------------- #

def probe_icmp(ip: str, timeout_ms: int = 1000) -> Optional[Dict[str, Any]]:
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
    try:
        start_time = time.perf_counter()
        proc = subprocess.run(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, text = True)
        rtt = round((time.perf_counter() - start_time) * 1000, 2)
        if proc.returncode == 0:
            ttl_match = re.search(r"TTL=(\d+)", proc.stdout, re.IGNORECASE)
            ttl = int(ttl_match.group(1)) if ttl_match else 0
            return {
                "ip": ip,
                "protocol": "ICMP",
                "mac": "N/A",
                "rtt_ms": rtt,
                "ttl": ttl,
                "os": resolve_os(ttl),
                "hostname": resolve_hostname(ip)
            }
    except Exception:
        pass
    return None

def probe_udp(ip: str, port: int = 53, timeout_sec: float = 1.0) -> Optional[Dict[str, Any]]:
    try:
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        dns_query = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
        sock.sendto(dns_query, (ip, port))
        data, _ = sock.recvfrom(512)
        rtt = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        return {
            "ip": ip,
            "protocol": f"UDP/{port}",
            "mac": "N/A",
            "rtt_ms": rtt,
            "ttl": 64,
            "os": resolve_os(64),
            "hostname": resolve_hostname(ip)
        }
    except socket.timeout:
        return None
    except Exception:
        return None

def probe_arp(subnet_str: str, timeout_sec: float = 2.0) -> List[Dict[str, Any]]:
    if not SCAPY_AVAILABLE:
        console.print(f"[bold #FFB86C][!] Scapy not found. Skipping ARP Sweep...")
        return []
    discovered = []
    try:
        pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = subnet_str)
        ans, _ = srp(pkt, timeout = timeout_sec, verbose = 0)
        for sent, received in ans:
            discovered.append({
                "ip": received.psrc,
                "protocol": "ARP",
                "mac": received.hwsrc.upper(),
                "rtt_ms": "<1.0",
                "ttl": 0,
                "os": "LAN Host",
                "hostname": resolve_hostname(received.psrc)
            })
    except Exception as e:
        pass
    return discovered

# ----- Target Parser -------------------------------------------- #

def parse_targets(target_input: str) -> List[str]:
    target_input = target_input.strip()
    if "://" in target_input or "/" in target_input and not any(c.isdigit() for c in target_input.split("/")[-1]):
        parsed = urlparse(target_input if "://" in target_input else f"http://{target_input}")
        target_input = parsed.hostname or target_input
    if ":" in target_input and not target_input.startswith("["):
        target_input = target_input.split(":", 1)[0]
    if "-" in target_input:
        start_str, end_str = target_input.split("-", 1)
        start_str = start_str.strip()
        end_str = end_str.strip()
        if "." not in end_str:
            base = ".".join(start_str.split(".")[:-1])
            end_str = f"{base}.{end_str}"
        try:
            start_int = int(ipaddress.IPv4Address(start_str))
            end_int = int(ipaddress.IPv4Address(end_str))
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]
        except ValueError:
            return []
    try:
        network = ipaddress.ip_network(target_input, strict = False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass
    try:
        resolved_ip = socket.gethostbyname(target_input)
        return [resolved_ip]
    except socket.gaierror:
        return []

# ----- Summary Table -------------------------------------------- #

def summary_table(target: str, hosts: List[Dict[str, Any]]) -> None:
    table = Table(
        title = f"[bold white]IPScan - Host Discovery Summary for {target}",
        border_style = "#C6ECE3",
        header_style = "#C6ECE3",
        expand = False
    )
    table.add_column("IP Address", style = "bold cyan", justify = "left")
    table.add_column("MAC Address", style = "white", justify = "left")
    table.add_column("Hostname", style = "dim white", justify = "left")
    table.add_column("Protocol", style = "green", justify = "center")
    table.add_column("Latency (ms)", style = "yellow", justify = "right")
    table.add_column("OS Estimate", style = "#C6ECE3", justify = "left")
    for host in hosts:
        table.add_row(
            host["ip"],
            host["mac"],
            host["hostname"],
            host["protocol"],
            str(host["rtt_ms"]),
            host["os"]
        )
    console.print()
    console.print(table)
    console.print(f"[#2ECC71][+] Host Discovery has been completed successfully!")
    console.print(f"[#2ECC71][+] IPScan identified {len(hosts)} active endpoints.")

# ----- Orchestration -------------------------------------------- #

def orchestrate(target: str, mode: str = "icmp", threads: int = 100, timeout_ms: int = 1000, output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    target_ips = parse_targets(target)
    if not target_ips:
        console.print(f"[bold #FF6B6B][!] Invalid IP target or subnet has been specified.")
        return []
    active_hosts: Dict[str, Dict[str, Any]] = {}
    if mode == "arp":
        if not SCAPY_AVAILABLE:
            console.print(f"[bold #FFB86C][!] Scapy is required for ARP scanning.")
            return []
        with console.status(f"[#BB9AF7][~] Executing layer 2 ARP broadcast sweep...", spinner = "dots"):
            arp_results = probe_arp(target, timeout_sec = 2.0)
            for res in arp_results:
                active_hosts[res["ip"]] = res
        console.print(f"[#2ECC71][+] ARP Broadcast completed successfully!")
    elif mode == "icmp":
        with console.status(f"[#BB9AF7][~] Executing ICMP sweep (using {threads} workers)...", spinner = "dots"):
            with concurrent.futures.ThreadPoolExecutor(max_workers = threads) as executor:
                futures = {executor.submit(probe_icmp, ip, timeout_ms): ip for ip in target_ips}
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        active_hosts[res["ip"]] = res
        console.print(f"[#2ECC71][+] ICMP Sweep completed successfully!")
    elif mode == "udp":
        udp_workers = min(50, threads)
        with console.status(f"[#BB9AF7][~] Executing UDP sweep (using {udp_workers} workers)...", spinner = "dots"):
            with concurrent.futures.ThreadPoolExecutor(max_workers = udp_workers) as executor:
                futures = {executor.submit(probe_udp, ip, 53, timeout_ms / 1000.0): ip for ip in target_ips}
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        active_hosts[res["ip"]] = res
        console.print(f"[#2ECC71][+] UDP Sweep completed successfully!")
    final_hosts = sorted(active_hosts.values(), key = lambda h: ipaddress.IPv4Address(h["ip"]))
    summary_table(target, final_hosts)
    if output_path:
        try:
            path = Path(output_path)
            path.parent.mkdir(parents = True, exist_ok = True)
            path.write_text(json.dumps(final_hosts, indent = 2))
            console.print(f"[#2ECC71][+] Report successfully written to [#BB9AF7]{output_path}[/#BB9AF7]")
        except Exception:
            console.print(f"[bold #FF6B6B][!] IPScan encountered an Error while saving the JSON Report")
    return final_hosts

# ----- ASCII Banner --------------------------------------------- #

def ascii() -> None:
    art_content = rf"""
ooooo ooooooooo.    .oooooo..o
`888' `888   `Y88. d8P'    `Y8
 888   888   .d88' Y88bo.       .ooooo.   .oooo.   ooo. .oo.
 888   888ooo88P'   `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b
 888   888              `"Y88b 888        .oP"888   888   888
 888   888         oo     .d8P 888   .o8 d8(  888   888   888
o888o o888o        8""88888P'  `Y8bod8P' `Y888""8o o888o o888o
"""
    art_color = Text(art_content, style = "#C6ECE3")
    art_panel = Panel(art_color, border_style = "#C6ECE3", expand = False)
    console.print(art_panel)
    banner_width = console.measure(art_panel).maximum
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print("  [~] Created by [bold red blink]Cursed271[/bold red blink]")
    console.print("  [~] IPScan - Find the hosts. Map the footholds.")
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print()
    return banner_width

# ----- Argument Parser ------------------------------------------ #

@app.command()
def argu(
    target: Optional[str] = typer.Option(None, "--target", "-t", help = "Enter the target CIDR, IP range, or single IP"),
    mode: str = typer.Option("icmp", "--mode", "-m", callback = validate_mode, help = "Enter the scan mode for IPScan [arp | icmp | udp]"),
    threads: int = typer.Option(100, "--threads", "-n", help = "Enter the Concurrency Limit for Workers"),
    timeout: int = typer.Option(1000, "--timeout", "-w", help = "Enter the Probing Timeout in Miliseconds"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help = "Enter the save path for the JSON export"),
) -> None:
    if not target:
        target = Prompt.ask(f"[#C6ECE3][?] Enter the IP Range, Subnet, or URL to scan (e.g. 192.168.1.0/24)")
    clean_target = target.strip()
    clean_output = output.strip() if output else None
    console.print(f"[#2ECC71][+] IPScan initiated a [bold white]{mode.upper()}[/bold white] scan against [bold white]{clean_target}[/bold white]")
    orchestrate(
        target = clean_target,
        mode = mode,
        threads = threads,
        timeout_ms = timeout,
        output_path = clean_output
    )

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    banner_width = ascii()
    typer_rich.MAX_WIDTH = banner_width
    app()

# ----- End ------------------------------------------------------ #