#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
import os
import socket
import sys
from scapy.all import ICMP, IP, TCP, UDP, sniff

# ANSI Color Codes for Kali Terminal Look
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def clear_screen():
  os.system("clear" if os.name == "posix" else "cls")


def banner():
  print(f"{CYAN}" + "=" * 60 + f"{RESET}")
  print(f"{CYAN}       KALI LINUX - NETWORK PACKET & PORT TOOL{RESET}")
  print(f"{CYAN}" + "=" * 60 + f"{RESET}")


# --- OPTION 1: PORT SCANNER ---
def run_port_scanner():
  clear_screen()
  print(f"{CYAN}[*] Starting Port Scanner Module...{RESET}\n")

  target = input("Enter Target IP or Domain to Scan: ").strip()
  if not target:
    print(f"{RED}[!] Error: No target provided.{RESET}")
    input("\nPress Enter to continue...")
    return

  try:
    target_ip = socket.gethostbyname(target)
  except socket.gaierror:
    print(f"\n{RED}[!] Error: Hostname '{target}' could not be resolved.{RESET}")
    input("\nPress Enter to continue...")
    return

  print("-" * 50)
  print(f"Scanning Target: {target_ip} ({target})")
  print(f"Port Range: 1 - 100")
  print(f"Time Started: {str(datetime.now())}")
  print("-" * 50)

  try:
    for port in range(1, 101):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(0.5)
      result = s.connect_ex((target_ip, port))

      if result == 0:
        print(f"{GREEN}[+] Port {port}: OPEN{RESET}")
      s.close()

    print("-" * 50)
    print(f"Scan Complete. Time: {str(datetime.now())}")

  except KeyboardInterrupt:
    print(f"\n{YELLOW}[!] Scan Interrupted by User.{RESET}")
  except socket.error:
    print(f"\n{RED}[!] Error: Could not connect to server.{RESET}")

  input("\nPress Enter to return to the main menu...")


# --- OPTION 2: PACKET SNIFFER ---
def packet_callback(packet):
  try:
    if packet.haslayer(IP):
      ip_layer = packet.getlayer(IP)
      src_ip = ip_layer.src
      dst_ip = ip_layer.dst

      proto_name = "OTHER"
      if packet.haslayer(TCP):
        proto_name = "TCP"
      elif packet.haslayer(UDP):
        proto_name = "UDP"
      elif packet.haslayer(ICMP):
        proto_name = "ICMP"

      print(f"{GREEN}[+] {proto_name} Packet:{RESET} {src_ip} ---> {dst_ip}")

      if packet.haslayer(TCP) or packet.haslayer(UDP):
        sport = packet.sport
        dport = packet.dport
        print(
            f"    {CYAN}Ports -> Source: {sport} | Destination:"
            f" {dport}{RESET}"
        )
      print("-" * 50)
  except Exception:
    pass


def run_packet_sniffer():
  clear_screen()
  print(f"{CYAN}[*] Starting Packet Sniffer Module...{RESET}")
  print(f"{YELLOW}[!] Note: Make sure you are running with 'sudo'.{RESET}\n")
  print(f"Time Started: {str(datetime.now())}")
  print(f"{YELLOW}[-] Press Ctrl+C to stop sniffing and return to menu.{RESET}\n")

  try:
    sniff(prn=packet_callback, store=False)
  except KeyboardInterrupt:
    print(f"\n\n{YELLOW}[!] Packet Sniffer Stopped by User.{RESET}")
  except PermissionError:
    print(
        f"\n{RED}[!] Error: Root privileges required! Please restart script"
        f" with 'sudo'.{RESET}"
    )

  input("\nPress Enter to return to the main menu...")


# --- MAIN MENU LOOP ---
def main():
  while True:
    clear_screen()
    banner()
    print(f"{GREEN}1.{RESET} Scan Network Ports")
    print(f"{GREEN}2.{RESET} Start Packet Sniffer")
    print(f"{RED}3.{RESET} Exit")
    print(f"{CYAN}" + "=" * 60 + f"{RESET}")

    choice = input(f"Select an option (1-3): ").strip()

    if choice == "1":
      run_port_scanner()
    elif choice == "2":
      run_packet_sniffer()
    elif choice == "3":
      print(f"\n{CYAN}[*] Exiting Tool. Good luck with your project!{RESET}")
      sys.exit(0)
    else:
      print(f"\n{RED}[!] Invalid choice! Please select 1, 2, or 3.{RESET}")
      input("\nPress Enter to continue...")


if __name__ == "__main__":
  main()
  