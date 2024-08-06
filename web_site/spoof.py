from scapy.all import ARP, Ether, srp
import re
from collections import defaultdict

def is_valid_mac(mac):
    """MAC adresinin geçerli bir formatta olup olmadığını kontrol eder."""
    mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return mac_regex.match(mac) is not None

def scan_network(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    arp_table = defaultdict(set)
    mac_to_ip_map = defaultdict(set)

    for element in answered_list:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }

        if not is_valid_mac(device_info["mac"]):
            device_info["mac"] = "Geçersiz MAC Adresi"
        
        devices_list.append(device_info)
        
        arp_table[device_info["ip"]].add(device_info["mac"])

        mac_to_ip_map[device_info["mac"]].add(device_info["ip"])

    spoofed_devices_list = []
    duplicate_mac_list = []

    for ip, macs in arp_table.items():
        # Aynı IP için birden fazla MAC adresi varsa, spoofing şüphesi
        if len(macs) > 1:
            spoofed_devices_list.append({
                "ip": ip,
                "macs": list(macs)
            })

    for mac, ips in mac_to_ip_map.items():
        # Aynı MAC adresi için birden fazla IP adresi varsa, sahtecilik şüphesi
        if len(ips) > 1:
            duplicate_mac_list.append({
                "mac": mac,
                "ips": list(ips)
            })

    return {
        "devices": devices_list,
        "spoofed": spoofed_devices_list,
        "duplicate_mac": duplicate_mac_list
    }
