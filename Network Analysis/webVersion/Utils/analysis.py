from scapy.all import IP, TCP, UDP, ICMP, IPv6, Raw

def extract_packet_info(packet):
    packet_info = {}
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['protocol'] = packet[IP].proto
    elif IPv6 in packet:
        packet_info['src_ip'] = packet[IPv6].src
        packet_info['dst_ip'] = packet[IPv6].dst
        packet_info['protocol'] = packet[IPv6].nh

    if TCP in packet:
        packet_info['protocol_name'] = 'TCP'
        packet_info['src_port'] = packet[TCP].sport
        packet_info['dst_port'] = packet[TCP].dport
    elif UDP in packet:
        packet_info['protocol_name'] = 'UDP'
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
    elif ICMP in packet:
        packet_info['protocol_name'] = 'ICMP'
    else:
        packet_info['protocol_name'] = 'Other'

    return packet_info

def extract_payload_data(packet):
    if Raw in packet:
        return packet[Raw].load.decode(errors='ignore')
    return ""

def analyze_packet(packet):
    packet_info = extract_packet_info(packet)
    payload_data = extract_payload_data(packet)

    analysis = {
        "source_ip": packet_info.get("src_ip", ""),
        "destination_ip": packet_info.get("dst_ip", ""),
        "protocol": packet_info.get("protocol_name", ""),
        "source_port": packet_info.get("src_port", ""),
        "destination_port": packet_info.get("dst_port", ""),
        "payload_data": payload_data[:100] if payload_data else ""  # limit payload length
    }

    return analysis

def analyze_capture(packet):
    return analyze_packet(packet)

def start_packet_analysis(interface, packet_count=10):
    from scapy.all import sniff
    packets = sniff(iface=interface, prn=None, count=packet_count, store=True)
    analyzed_packets = [analyze_capture(pkt) for pkt in packets]
   
    return analyzed_packets
