import socket
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup


def scan_network():

    target_ip = "192.168.0.1/24"

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc

        # Hostname lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # Vendor lookup
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown Vendor"

        # AI classification
        device_type = classify_device(hostname, vendor)

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_type": device_type
        })

    return devices


def classify_device(hostname, vendor):

    hostname = hostname.lower()
    vendor = vendor.lower()

    # Hostname rules
    if "desktop" in hostname:
        return "Windows PC"

    elif "android" in hostname:
        return "Android Phone"

    elif "iphone" in hostname:
        return "iPhone"

    # Vendor rules
    elif "samsung" in vendor:
        return "Samsung Device"

    elif "xiaomi" in vendor:
        return "Android Phone"

    elif "apple" in vendor:
        return "Apple Device"

    elif "tenda" in vendor:
        return "Wi-Fi Router"

    elif "intel" in vendor:
        return "Laptop / PC"

    elif "dell" in vendor:
        return "Dell Laptop"

    elif hostname == "unknown":
        return "Unknown Network Device"

    else:
        return "Possible IoT Device"


devices = scan_network()

print("\n🧠 AI Device Classification System\n")

for device in devices:

    print(f"IP Address   : {device['ip']}")
    print(f"MAC Address  : {device['mac']}")
    print(f"Hostname     : {device['hostname']}")
    print(f"Vendor       : {device['vendor']}")
    print(f"Device Type  : {device['device_type']}")

    print("-" * 60)