import time
import csv
import requests
import signal
from datetime import datetime
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP

# Network Configuration
INTERFACE = "eth0"  # Comamnd to check interface = ip a
SERVER_IP = "192.168.1.20"  # Change this to your target server
SERVER_URL = f"http://{SERVER_IP}/"
CSV_FILENAME = "network_metrics.csv"

# Delays between HTTP requests in seconds
REQUEST_DELAYS = [1, 2, 1, 4, 3, 2, 8, 2, 3, 1]

# Metrics Storage
rtt_values = []
arp_replies = {"solicited": 0, "unsolicited": 0}
packet_symmetry = {"symmetric": 0, "asymmetric": 0}
log_entries = []  # Temporary storage for log entries
stop_signal = False


def capture_arp_packets(packet):
    """Capture ARP replies and classify them as solicited or unsolicited."""
    global arp_replies
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        if packet[ARP].psrc == packet[ARP].pdst:
            arp_replies["unsolicited"] += 1
        else:
            arp_replies["solicited"] += 1


def analyze_packet_symmetry(packet):
    """Detect symmetric or asymmetric paths based on IP packet responses."""
    global packet_symmetry
    if packet.haslayer(IP):
        if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # ICMP Echo Reply
            packet_symmetry["symmetric"] += 1
        else:
            packet_symmetry["asymmetric"] += 1


def measure_http_rtt():
    """Measure HTTP Round-Trip Time (RTT)."""
    start_time = time.time()
    try:
        response = requests.get(SERVER_URL, timeout=2)
        end_time = time.time()
        rtt = end_time - start_time
        rtt_values.append(rtt)
        return rtt
    except requests.exceptions.RequestException:
        return None  # If there is a timeout or connection issue


def initialize_csv():
    """Initialize the CSV file with headers."""
    with open(CSV_FILENAME, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "round-trip-time", "arp-solicited", "arp-unsolicited", "path-symmetric", "path-asymmetric"])


def log_to_csv():
    """Write collected metrics to the CSV file."""
    with open(CSV_FILENAME, "a", newline="") as file:
        writer = csv.writer(file)
        for entry in log_entries:
            writer.writerow(entry)
    log_entries.clear()  # Clear temporary storage


def sniff_packets():
    """Sniff network packets and analyze ARP and path symmetry."""
    sniff(prn=capture_arp_packets, store=False, filter="arp", iface=INTERFACE, timeout=60)
    sniff(prn=analyze_packet_symmetry, store=False, filter="icmp", iface=INTERFACE, timeout=60)


def run():
    """Main loop for network monitoring."""
    while not stop_signal:
        sniff_packets()  # Sniff ARP and ICMP packets
        for delay in REQUEST_DELAYS:
            if stop_signal:
                break

            rtt = measure_http_rtt()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Log the collected data
            log_entries.append(
                [timestamp, rtt, arp_replies["solicited"], arp_replies["unsolicited"], packet_symmetry["symmetric"],
                 packet_symmetry["asymmetric"]])

            print(
                f"[{timestamp}] RTT: {rtt:.5f} sec, Solicited ARP: {arp_replies['solicited']}, "
                f"Unsolicited ARP: {arp_replies['unsolicited']}, Symmetric: {packet_symmetry['symmetric']}, "
                f"Asymmetric: {packet_symmetry['asymmetric']}")

            time.sleep(delay)


def handle_interrupt(signum, frame):
    """Handle KeyboardInterrupt (Ctrl+C) to safely write logs to CSV."""
    global stop_signal
    print("\n[INFO] Stopping network monitoring...")
    stop_signal = True
    log_to_csv()
    print(f"[INFO] Metrics saved in {CSV_FILENAME}")
    exit(0)


# Main execution
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)  # Handle Ctrl+C
    initialize_csv()
    run()
