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

    dest_ports = []

    for packet in packets:
        # check for tcp layer and extract destination port
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            dest_ports.append(port)
            # this line is strictly here as the original program also has this
            print(f"TCP.dst_port = {port}")

        # check for udp layer and extract destination port
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
            dest_ports.append(port)
            # this line is strictly here as the original program also has this
            print(f"UDP.dst_port = {port}")
    
    # we find all the unique ports by using the property of sets 
    # and then just convert the set into a list and then sort it.
    unique_ports = sorted(list(set(dest_ports)))
    
    print("\n--- Summary ---")
    print(f"Unique Destination Ports: {unique_ports}")


if __name__ == "__main__":
    FILENAME = "tests/slowdownload.pcap"
    parse_pcap(FILENAME)