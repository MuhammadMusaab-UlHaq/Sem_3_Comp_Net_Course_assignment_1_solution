from scapy.all import rdpcap, TCP, UDP
import collections

def parse_pcap(filename):
    """
    Parses a PCAP file to extract and list unique TCP/UDP destination ports.
    """
    print(f"--- Analyzing {filename} ---")
    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return

    # using dictionary for storing frequencies
    port_counts = {}

    for packet in packets:
        port = None
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            print(f"TCP.dst_port = {port}")
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
            print(f"UDP.dst_port = {port}")

        if port is not None:
            # incrementing frequency if found
            port_counts[port] = port_counts.get(port, 0) + 1

    # summary time
    print("\n--- Destination Port Frequency (Sorted) ---")

    # sort the ports and then print them one by one.
    sorted_ports = sorted(port_counts.keys())

    if not sorted_ports:
        print("No TCP or UDP packets found.")
    else:
        for port in sorted_ports:
            count = port_counts[port]
            print(f"Port {port} -> {count} packets")


if __name__ == "__main__":
    FILENAME = "tests/slowdownload.pcap"
    parse_pcap(FILENAME)