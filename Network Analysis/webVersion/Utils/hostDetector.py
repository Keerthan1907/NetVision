import ipaddress
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

def get_mac_vendor(mac):   
    try:
        vendor = MacLookup().lookup(mac)  
    except:
        vendor = "Unknown"

    # Normalize known virtualization vendors
    if vendor in ["PCS Systemtechnik GmbH", "Oracle Corp"]:
        vendor = "Virtual Box"
    
    return vendor

def detect_live_hosts(local_ip):
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        target_ip = f"{network.network_address}/24"
        
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast Ethernet frame
        arp = ARP(pdst=target_ip)
        packet = ethernet / arp

        result = srp(packet, timeout=10, verbose=False)[0]  # Send ARP and collect replies

        live_hosts = []
        for _, received in result:
            host_info = {
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": get_mac_vendor(received.hwsrc)
            }
            live_hosts.append(host_info)

        return {
            "status": "success",
            "local_ip": local_ip,
            "network_range": str(network),
            "hosts": live_hosts
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
