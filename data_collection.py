import csv
import requests
import signal
import threading
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import *

# Network Configuration
INTERFACE = "ens33"               # Network interface for sniffing
SERVER_IP = "192.168.1.20"         # Target web server IP for tests
SERVER_URL = f"http://{SERVER_IP}/"
CSV_FILENAME = "network_metrics.csv"

# Metrics Storage (cumulative counters)
arp_replies = {"solicited": 0, "unsolicited": 0}
packet_loss = {"sent": 0, "lost": 0}

# Temporary counters for correlating ARP requests and replies
arp_requests_sent = defaultdict(int)      # Count ARP requests sent per IP
arp_replies_received = defaultdict(int)     # Count ARP replies received per IP

stop_signal = False

# Previous cumulative values for calculating deltas
previous_metrics = {
    "arp_solicited": 0,
    "arp_unsolicited": 0,
    "lost_packets": 0,
    "total_packets": 0,
}

def initialize_csv():
    """Initialize the CSV file with headers."""
    with open(CSV_FILENAME, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "timestamp", "round-trip-time", "delta_arp_solicited", "delta_arp_unsolicited",
            "delta_lost_packets", "delta_total_packets"
        ])

def log_to_csv(rtt, delta_arp_solicited, delta_arp_unsolicited, delta_lost_packets, delta_total_packets):
    """Append one log row with current metrics to the CSV file."""
    with open(CSV_FILENAME, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            rtt,
            delta_arp_solicited,
            delta_arp_unsolicited,
            delta_lost_packets,
            delta_total_packets
        ])
    print(f"[INFO] Logged data at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def track_arp_requests(packet):
    """Track outgoing ARP requests."""
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP Request
        target_ip = packet[ARP].pdst
        arp_requests_sent[target_ip] += 1

def capture_arp_packets(packet):
    """Capture incoming ARP replies and classify them as solicited or unsolicited."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        source_ip = packet[ARP].psrc
        arp_replies_received[source_ip] += 1
        # If the number of replies exceeds the requests sent, count as unsolicited
        if arp_replies_received[source_ip] > arp_requests_sent.get(source_ip, 0):
            arp_replies["unsolicited"] += 1
        else:
            arp_replies["solicited"] += 1

def arp_sniffer():
    """Continuously sniff ARP packets."""
    sniff(prn=lambda pkt: (track_arp_requests(pkt), capture_arp_packets(pkt)),
          store=False, filter="arp", iface=INTERFACE, verbose=False)

def perform_packet_loss_test():
    """Perform an ICMP ping test and update packet loss counters."""
    total_sent = 5
    lost = 0
    for _ in range(total_sent):
        pkt = IP(dst=SERVER_IP) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply is None:
            lost += 1
    packet_loss["sent"] += total_sent
    packet_loss["lost"] += lost
    return total_sent, lost

def perform_http_rtt_test():
    """Perform an HTTP GET request and measure the round-trip time."""
    try:
        start_time = time.time()
        response = requests.get(SERVER_URL, timeout=2)
        rtt = time.time() - start_time
    except requests.exceptions.RequestException:
        rtt = "N/A"
    return rtt

def handle_interrupt(signum, frame):
    """Handle Ctrl+C for graceful shutdown."""
    global stop_signal
    stop_signal = True
    print("[INFO] Exiting...")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)
    initialize_csv()

    # Start ARP sniffing in a separate thread
    threading.Thread(target=arp_sniffer, daemon=True).start()

    # Main thread: perform RTT and packet loss tests every 5 seconds and log results
    while not stop_signal:
        cycle_start = time.time()

        # Perform tests
        rtt = perform_http_rtt_test()
        total_sent, lost = perform_packet_loss_test()

        # Calculate deltas for ARP replies and packet loss
        delta_arp_solicited = arp_replies["solicited"] - previous_metrics["arp_solicited"]
        delta_arp_unsolicited = arp_replies["unsolicited"] - previous_metrics["arp_unsolicited"]
        delta_lost_packets = packet_loss["lost"] - previous_metrics["lost_packets"]
        delta_total_packets = packet_loss["sent"] - previous_metrics["total_packets"]

        # Log all test results with the same timestamp
        log_to_csv(rtt, delta_arp_solicited, delta_arp_unsolicited, delta_lost_packets, delta_total_packets)

        # Update previous metrics for the next cycle
        previous_metrics["arp_solicited"] = arp_replies["solicited"]
        previous_metrics["arp_unsolicited"] = arp_replies["unsolicited"]
        previous_metrics["lost_packets"] = packet_loss["lost"]
        previous_metrics["total_packets"] = packet_loss["sent"]

        # Reset temporary ARP counters so each cycle captures only new data
        arp_requests_sent.clear()
        arp_replies_received.clear()

        # Sleep to ensure a 5-second cycle (account for time taken by tests)
        elapsed = time.time() - cycle_start
        if elapsed < 5:
            time.sleep(5 - elapsed)
