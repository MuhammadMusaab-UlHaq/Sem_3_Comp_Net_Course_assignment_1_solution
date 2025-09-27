from scapy.all import rdpcap, TCP, UDP, IP
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

    # using dictionaries for storing frequencies
    port_counts = {}
    ip_port_counts = {}  # another dictionary for IP:Port combo

    for packet in packets:
        # we get the IP packets
        if packet.haslayer(IP):
            dst_ip = packet[IP].dst
            port = None
            
            if packet.haslayer(TCP):
                port = packet[TCP].dport
                print(f"TCP.dst_port = {port}")
            elif packet.haslayer(UDP):
                port = packet[UDP].dport
                print(f"UDP.dst_port = {port}")

            if port is not None:
                # add port count
                port_counts[port] = port_counts.get(port, 0) + 1
                
                # make composite key for ip
                key = f"{dst_ip}:{port}"
                ip_port_counts[key] = ip_port_counts.get(key, 0) + 1

    # summary time
    print("\n--- Destination Port Frequency (Sorted) ---")

    # sort the ports and then print all the stuff them one by one.
    sorted_ports = sorted(port_counts.keys())

    if not sorted_ports:
        print("No TCP or UDP packets found.")
    else:
        for port in sorted_ports:
            count = port_counts[port]
            print(f"Port {port} -> {count} packets")

    print("\n--- Destination IP and Port Frequency ---")
    for key, count in sorted(ip_port_counts.items()):
        print(f"{key} -> {count} packets")


if __name__ == "__main__":
    FILENAME = "tests/slowdownload.pcap"
    parse_pcap(FILENAME)