import csv
import requests
import signal
import time
from datetime import datetime
from scapy.all import *

# Network Configuration
INTERFACE = "ens33"  # Command to check interface = ip a
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
        # Debug: show packet details
        print(f"[DEBUG] ARP packet captured: psrc={packet[ARP].psrc}, pdst={packet[ARP].pdst}")
        if packet[ARP].psrc == packet[ARP].pdst:
            arp_replies["unsolicited"] += 1
            print("[DEBUG] Classified ARP as unsolicited")
        else:
            arp_replies["solicited"] += 1
            print("[DEBUG] Classified ARP as solicited")

def analyze_packet_symmetry(packet):
    """Detect symmetric or asymmetric paths based on IP packet responses."""
    global packet_symmetry
    if packet.haslayer(IP):
        if packet.haslayer(ICMP) and packet[ICMP].type == 0:  # ICMP Echo Reply
            packet_symmetry["symmetric"] += 1
            print("[DEBUG] Packet classified as symmetric (ICMP Echo Reply)")
        else:
            packet_symmetry["asymmetric"] += 1
            print("[DEBUG] Packet classified as asymmetric (Non-ICMP Echo)")

def measure_http_rtt():
    """Measure HTTP Round-Trip Time (RTT)."""
    start_time = time.time()
    print(f"[DEBUG] Sending HTTP GET request to {SERVER_URL}")
    try:
        response = requests.get(SERVER_URL, timeout=2)
        end_time = time.time()
        rtt = end_time - start_time
        rtt_values.append(rtt)
        print(f"[DEBUG] HTTP response received in {rtt:.5f} seconds")
        return rtt
    except requests.exceptions.RequestException as e:
        print(f"[DEBUG] HTTP request failed: {e}")
        return None  # If there is a timeout or connection issue

def initialize_csv():
    """Initialize the CSV file with headers."""
    try:
        with open(CSV_FILENAME, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["timestamp", "round-trip-time", "arp-solicited", "arp-unsolicited", "path-symmetric", "path-asymmetric"])
        print(f"[DEBUG] CSV file {CSV_FILENAME} initialized with headers.")
    except Exception as e:
        print(f"[DEBUG] Failed to initialize CSV file: {e}")

def log_to_csv():
    """Write collected metrics to the CSV file."""
    if not log_entries:
        print("[DEBUG] No new log entries to write.")
        return
    try:
        with open(CSV_FILENAME, "a", newline="") as file:
            writer = csv.writer(file)
            for entry in log_entries:
                writer.writerow(entry)
        print(f"[DEBUG] Wrote {len(log_entries)} log entries to CSV file {CSV_FILENAME}.")
        log_entries.clear()  # Clear temporary storage after writing
    except Exception as e:
        print(f"[DEBUG] Failed to write to CSV file: {e}")

def sniff_packets():
    """Sniff network packets and analyze ARP and path symmetry."""
    print(f"[DEBUG] Starting ARP packet sniffing on interface {INTERFACE} for 60 seconds.")
    sniff(prn=capture_arp_packets, store=False, filter="arp", iface=INTERFACE, timeout=60)
    print(f"[DEBUG] Starting ICMP packet sniffing on interface {INTERFACE} for 60 seconds.")
    sniff(prn=analyze_packet_symmetry, store=False, filter="icmp", iface=INTERFACE, timeout=60)

def run():
    """Main loop for network monitoring."""
    global stop_signal
    print("[DEBUG] Starting network monitoring loop.")
    while not stop_signal:
        print("[DEBUG] Beginning new monitoring cycle: sniffing packets...")
        sniff_packets()  # Sniff ARP and ICMP packets
        print("[DEBUG] Finished packet sniffing cycle. Starting HTTP requests...")
        for delay in REQUEST_DELAYS:
            if stop_signal:
                break
            print(f"[DEBUG] Preparing to send HTTP request with a delay of {delay} seconds.")
            rtt = measure_http_rtt()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry = [timestamp, rtt, arp_replies["solicited"], arp_replies["unsolicited"],
                     packet_symmetry["symmetric"], packet_symmetry["asymmetric"]]
            log_entries.append(entry)
            print(f"[INFO] [{timestamp}] RTT: {rtt:.5f} sec, Solicited ARP: {arp_replies['solicited']}, "
                  f"Unsolicited ARP: {arp_replies['unsolicited']}, Symmetric: {packet_symmetry['symmetric']}, "
                  f"Asymmetric: {packet_symmetry['asymmetric']}")
            log_to_csv()  # Write log entry immediately to CSV
            time.sleep(delay)
        print("[DEBUG] Monitoring cycle complete. Continuing to next cycle...")

def handle_interrupt(signum, frame):
    """Handle KeyboardInterrupt (Ctrl+C) to safely write logs to CSV."""
    global stop_signal
    print("\n[INFO] KeyboardInterrupt received. Stopping network monitoring...")
    stop_signal = True
    log_to_csv()  # Write any remaining log entries
    print(f"[INFO] Metrics saved in {CSV_FILENAME}")
    exit(0)

# Main execution
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)  # Handle Ctrl+C
    initialize_csv()
    run()