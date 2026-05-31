from manuf import manuf

parser = manuf.MacParser()

mac_address = "BC:EE:7B:00:00:00"

vendor = parser.get_manuf(mac_address)
company = parser.get_comment(mac_address)

# Device type mapping
device_map = {
    "Apple": "Mobile / Laptop",
    "Samsung": "Mobile",
    "Xiaomi": "Mobile",
    "Realtek": "Network Device",
    "Cisco": "Router / Switch",
    "ASUSTek": "Router / Laptop",
    "TP-Link": "Router",
    "Huawei": "Mobile / Router",
    "Dell": "Laptop/Desktop",
    "HP": "Laptop/Desktop",
    "Lenovo": "Laptop/Desktop",
    "Intel": "Computer",
    "Amazon": "IoT Device",
}

device_type = "Unknown"

for key, value in device_map.items():
    if company and key.lower() in company.lower():
        device_type = value
        break

print(f"MAC Address : {mac_address}")
print(f"Vendor      : {vendor}")
print(f"Company     : {company}")
print(f"Device Type : {device_type}")