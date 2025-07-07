from scapy.all import IP, ICMP, TCP, UDP

def packet_filter(packet, filter_criteria):
    if 'src_ip' in filter_criteria:
        if packet.haslayer(IP) and packet[IP].src != filter_criteria['src_ip']:
            return False

    if 'dst_ip' in filter_criteria:
        if packet.haslayer(IP) and packet[IP].dst != filter_criteria['dst_ip']:
            return False

    if 'protocol' in filter_criteria:
        proto = filter_criteria['protocol'].upper()
        if proto == 'TCP' and not packet.haslayer(TCP):
            return False
        elif proto == 'UDP' and not packet.haslayer(UDP):
            return False
        elif proto == 'ICMP' and not packet.haslayer(ICMP):
            return False

    if 'src_port' in filter_criteria:
        if packet.haslayer(TCP) and packet[TCP].sport != filter_criteria['src_port']:
            return False
        if packet.haslayer(UDP) and packet[UDP].sport != filter_criteria['src_port']:
            return False

    if 'dst_port' in filter_criteria:
        if packet.haslayer(TCP) and packet[TCP].dport != filter_criteria['dst_port']:
            return False
        if packet.haslayer(UDP) and packet[UDP].dport != filter_criteria['dst_port']:
            return False

    if 'icmp_type' in filter_criteria:
        if packet.haslayer(ICMP) and packet[ICMP].type != filter_criteria['icmp_type']:
            return False

    return True

def parse_filter_string(filter_str):
    filter_dict = {}

    if not filter_str:
        return filter_dict

    conditions = filter_str.split(' and ')
    for condition in conditions:
        condition = condition.strip().lower()

        if condition.startswith('src host'):
            ip = condition.split(' ')[2]
            filter_dict['src_ip'] = ip
        elif condition.startswith('dst host'):
            ip = condition.split(' ')[2]
            filter_dict['dst_ip'] = ip
        elif condition == 'tcp':
            filter_dict['protocol'] = 'TCP'
        elif condition == 'udp':
            filter_dict['protocol'] = 'UDP'
        elif condition == 'icmp':
            filter_dict['protocol'] = 'ICMP'

    return filter_dict
