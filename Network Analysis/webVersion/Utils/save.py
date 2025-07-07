# tusharpawar749964@gmail.com
from scapy.all import wrpcap

def save_to_txt(captured_packets, filename):
    try:
        with open(filename, 'w') as f:
            for packet in captured_packets:
                f.write(packet.summary() + '\n')
        return {
            "status": "success",
            "message": f"Packets saved to {filename}",
            "file_type": "txt",
            "file_path": filename
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error saving packets to TXT: {str(e)}"
        }

def save_to_pcap(captured_packets, filename):
    try:
        wrpcap(filename, captured_packets)
        return {
            "status": "success",
            "message": f"Packets saved to {filename}",
            "file_type": "pcap",
            "file_path": filename
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error saving packets to PCAP: {str(e)}"
        }
