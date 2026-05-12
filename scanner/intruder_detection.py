import json
from scapy.all import ARP, Ether, srp


def scan_network():
    target_ip = "192.168.0.1/24"

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []

    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc.lower()
        })

    return devices


# Load trusted devices
with open("scanner/trusted_devices.json", "r") as file:
    trusted_devices = json.load(file)


# Scan network
devices = scan_network()

print("\n📡 Connected Devices:\n")

intruder_found = False

print(f"\n✅ Total Devices Found: {len(devices)}\n")


for device in devices:

    print(f"IP: {device['ip']} | MAC: {device['mac']}")

    # Intruder detection
    if device["mac"] not in trusted_devices:

        intruder_found = True

        print("\n🚨 SECURITY ALERT 🚨")
        print("Unknown device connected to Wi-Fi network")

        print(f"⚠️ Intruder IP: {device['ip']}")
        print(f"⚠️ Intruder MAC: {device['mac']}")

        print("-" * 50)

        # Save alert to file
        with open("alerts/intruder_alerts.txt", "a") as file:

            file.write(
                f"Intruder Detected | "
                f"IP: {device['ip']} | "
                f"MAC: {device['mac']}\n"
            )


if not intruder_found:
    print("\n✅ No intruders detected")