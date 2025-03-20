import csv
import requests
import signal
import time
import threading
from datetime import datetime
from collections import defaultdict
from scapy.all import *

# Network Configuration
INTERFACE = "ens33"  # Network interface for sniffing
SERVER_IP = "192.168.1.20"  # Target web server for HTTP requests
SERVER_URL = f"http://{SERVER_IP}/"
CSV_FILENAME = "network_metrics.csv"

# Metrics Storage
rtt_values = []
arp_replies = {"solicited": 0, "unsolicited": 0}
packet_loss = {"sent": 0, "lost": 0}
arp_requests_sent = defaultdict(int)  # Count ARP requests sent per IP
arp_replies_received = defaultdict(int)  # Count ARP replies received per IP
log_entries = []  # Temporary storage for log entries
stop_signal = False


def initialize_csv():
    """Initialize the CSV file with headers."""
    with open(CSV_FILENAME, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["round-trip-time", "arp-solicited", "arp-unsolicited", "lost-packets", "total-packets"])


def log_to_csv():
    """Write collected metrics to the CSV file."""
    with open(CSV_FILENAME, "a", newline="") as file:
        writer = csv.writer(file)
        total_packets = packet_loss["sent"]
        lost_packets = packet_loss["lost"]
        rtt = rtt_values[-1] if rtt_values else "N/A"
        writer.writerow([rtt, arp_replies["solicited"], arp_replies["unsolicited"], lost_packets, total_packets])
    print(
        f"[INFO] Logged data to CSV: RTT={rtt}, Solicited ARP={arp_replies['solicited']}, Unsolicited ARP={arp_replies['unsolicited']}, Lost Packets={lost_packets}, Total Packets={total_packets}")


def track_arp_requests(packet):
    """Track outgoing ARP requests."""
    global arp_requests_sent
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP Request
        target_ip = packet[ARP].pdst
        arp_requests_sent[target_ip] += 1  # Increment request count


def capture_arp_packets(packet):
    """Capture ARP replies and classify them based on request-reply balance."""
    global arp_replies
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        source_ip = packet[ARP].psrc
        arp_replies_received[source_ip] += 1
        unsolicited_replies = arp_replies_received[source_ip] - arp_requests_sent.get(source_ip, 0)
        if unsolicited_replies > 0:
            arp_replies["unsolicited"] += 1
        else:
            arp_replies["solicited"] += 1


def reset_arp_counters():
    """Periodically reset ARP counters to maintain real-time tracking."""
    global stop_signal
    while not stop_signal:
        time.sleep(10)  # Reset every 10 seconds
        arp_requests_sent.clear()
        arp_replies_received.clear()


def arp_sniffer():
    """Continuously sniff ARP packets in a separate thread."""
    sniff(prn=lambda pkt: (track_arp_requests(pkt), capture_arp_packets(pkt)), store=False, filter="arp",
          iface=INTERFACE)


def measure_packet_loss():
    """Continuously measure packet loss in a separate thread."""
    global stop_signal
    while not stop_signal:
        total_sent = 5
        lost_packets = 0
        for _ in range(total_sent):
            pkt = IP(dst=SERVER_IP) / ICMP()
            reply = sr1(pkt, timeout=1, verbose=False)
            if reply is None:
                lost_packets += 1
        packet_loss["sent"] += total_sent
        packet_loss["lost"] += lost_packets
        log_to_csv()
        time.sleep(5)


def measure_http_rtt():
    """Continuously measure HTTP RTT in a separate thread."""
    global stop_signal
    while not stop_signal:
        try:
            start_time = time.time()
            response = requests.get(SERVER_URL, timeout=2)
            end_time = time.time()
            rtt_values.append(end_time - start_time)
        except requests.exceptions.RequestException:
            pass
        log_to_csv()
        time.sleep(2)


def handle_interrupt(signum, frame):
    """Handle KeyboardInterrupt (Ctrl+C) to safely write logs to CSV."""
    global stop_signal
    stop_signal = True
    log_to_csv()
    exit(0)


# Main execution
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)  # Handle Ctrl+C
    initialize_csv()

    threading.Thread(target=arp_sniffer, daemon=True).start()
    threading.Thread(target=measure_packet_loss, daemon=True).start()
    threading.Thread(target=measure_http_rtt, daemon=True).start()
    threading.Thread(target=reset_arp_counters, daemon=True).start()

    while not stop_signal:
        time.sleep(1)
