
# =============================================================================
# Assignment 1 – Parsing PCAP Files
# Partner 1:  Hamza Muhammad Iqbal (503052)
# Partner 2:  Muhammad Musaab Ul Haq (501739)
#
# Learnings & Challenges:
#  We learned to use the Scapy library in Python to parse network capture files.
#  A key learning was how to iterate through packets and access specific protocol 
#  layers like IP, TCP, and UDP to extract headers such as destination port and IP.
#  We also practiced using dictionaries for frequency counting, which is very 
#  efficient.
#  A challenge was setting up the environment and understanding how to access
#  Scapy's layered packet objects, but this became clear once we saw scapy 
#  documentation [https://scapy.readthedocs.io/].
#  Implementing command-line arguments with `argparse` was a new skill that made 
#  our script much more professional and reusable.
# =============================================================================

import argparse
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
    except Exception as e:
        print(f"Error: Failed to read or parse the file '{filename}'.")
        print(f"Details: {e}")
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
            elif packet.haslayer(UDP):
                port = packet[UDP].dport

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
    parser = argparse.ArgumentParser(description="Parse a PCAP file to analyze TCP/UDP destination ports.")
    parser.add_argument("filename", help="The path to the .pcap file to analyze.")
    args = parser.parse_args()
    parse_pcap(args.filename)