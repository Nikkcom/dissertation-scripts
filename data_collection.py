import requests
import signal

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


def track_arp_requests(packet):
    """Track outgoing ARP requests."""
    global arp_requests_sent
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP Request
        target_ip = packet[ARP].pdst
        arp_requests_sent[target_ip] += 1  # Increment request count
        print(f"[DEBUG] ARP request sent to {target_ip} (Total: {arp_requests_sent[target_ip]})")


def capture_arp_packets(packet):
    """Capture ARP replies and classify them based on request-reply balance."""
    global arp_replies
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        source_ip = packet[ARP].psrc
        dest_ip = packet[ARP].pdst
        source_mac = packet[ARP].hwsrc
        print(f"[DEBUG] ARP reply received: {source_ip} ({source_mac}) -> {dest_ip}")

        # Increment the reply count for this IP
        arp_replies_received[source_ip] += 1

        # Calculate unsolicited replies
        unsolicited_replies = arp_replies_received[source_ip] - arp_requests_sent.get(source_ip, 0)

        if unsolicited_replies > 0:
            arp_replies["unsolicited"] += 1
            print(
                f"[WARNING] Unsolicited ARP replies detected from {source_ip} (Excess replies: {unsolicited_replies})")
        else:
            arp_replies["solicited"] += 1
            print("[DEBUG] Classified ARP as solicited")


def reset_arp_counters():
    """Periodically reset ARP counters to maintain real-time tracking."""
    global stop_signal
    while not stop_signal:
        time.sleep(10)  # Reset every 10 seconds
        arp_requests_sent.clear()
        arp_replies_received.clear()
        print("[DEBUG] Reset ARP request and reply counters.")


def arp_sniffer():
    """Continuously sniff ARP packets in a separate thread."""
    print(f"[DEBUG] Starting continuous ARP sniffing on interface {INTERFACE}.")
    sniff(prn=lambda pkt: (track_arp_requests(pkt), capture_arp_packets(pkt)), store=False, filter="arp",
          iface=INTERFACE)


def measure_packet_loss():
    """Continuously measure packet loss in a separate thread."""
    global stop_signal
    while not stop_signal:
        total_sent = 5
        lost_packets = 0
        print("[DEBUG] Measuring packet loss...")
        for _ in range(total_sent):
            pkt = IP(dst=SERVER_IP) / ICMP()
            reply = sr1(pkt, timeout=1, verbose=False)
            if reply is None:
                lost_packets += 1
                print("[DEBUG] Packet lost")
        packet_loss["sent"] += total_sent
        packet_loss["lost"] += lost_packets
        print(f"[INFO] Packet loss: {lost_packets}/{total_sent} packets lost.")
        time.sleep(5)  # Adjust as necessary


def measure_http_rtt():
    """Continuously measure HTTP RTT in a separate thread."""
    global stop_signal
    while not stop_signal:
        print(f"[DEBUG] Sending HTTP GET request to {SERVER_URL}")
        try:
            start_time = time.time()
            response = requests.get(SERVER_URL, timeout=2)
            end_time = time.time()
            rtt = end_time - start_time
            rtt_values.append(rtt)
            print(f"[DEBUG] HTTP response received in {rtt:.5f} seconds")
        except requests.exceptions.RequestException as e:
            print(f"[DEBUG] HTTP request failed: {e}")
        time.sleep(2)  # Adjust as necessary


def handle_interrupt(signum, frame):
    """Handle KeyboardInterrupt (Ctrl+C) to safely write logs to CSV."""
    global stop_signal
    print("\n[INFO] KeyboardInterrupt received. Stopping network monitoring...")
    stop_signal = True
    log_to_csv()
    print(f"[INFO] Metrics saved in {CSV_FILENAME}")
    exit(0)


# Main execution
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)  # Handle Ctrl+C
    initialize_csv()

    # Start ARP sniffing in a separate thread
    arp_thread = threading.Thread(target=arp_sniffer, daemon=True)
    arp_thread.start()

    # Start packet loss measurement in a separate thread
    packet_loss_thread = threading.Thread(target=measure_packet_loss, daemon=True)
    packet_loss_thread.start()

    # Start HTTP RTT measurement in a separate thread
    rtt_thread = threading.Thread(target=measure_http_rtt, daemon=True)
    rtt_thread.start()

    # Start ARP counter reset thread
    arp_reset_thread = threading.Thread(target=reset_arp_counters, daemon=True)
    arp_reset_thread.start()

    # Keep the main thread running
    while not stop_signal:
        time.sleep(1)
