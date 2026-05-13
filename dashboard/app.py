import streamlit as st
import pandas as pd
import socket
import json
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup


# -----------------------------
# Scan Network
# -----------------------------
def scan_network():

    target_ip = "192.168.0.1/24"

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    #result = srp(packet, timeout=3, verbose=0)[0]
    result = srp(packet, timeout=8, verbose=0)[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc.lower()

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
            "IP Address": ip,
            "MAC Address": mac,
            "Hostname": hostname,
            "Vendor": vendor,
            "Device Type": device_type
        })

    # Always return consistent columns
    return pd.DataFrame(
        devices,
        columns=[
            "IP Address",
            "MAC Address",
            "Hostname",
            "Vendor",
            "Device Type"
        ]
    )


# -----------------------------
# AI Device Classification
# -----------------------------
def classify_device(hostname, vendor):

    hostname = hostname.lower()
    vendor = vendor.lower()

    if "desktop" in hostname:
        return "Windows PC"

    elif "android" in hostname:
        return "Android Phone"

    elif "iphone" in hostname:
        return "iPhone"

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


# -----------------------------
# Load Trusted Devices
# -----------------------------
with open("scanner/trusted_devices.json", "r") as file:
    trusted_devices = json.load(file)


# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(
    page_title="AI Network Watcher",
    layout="wide"
)

st.title("📡 AI Network Watcher")

st.markdown("### Real-Time Wi-Fi Monitoring Dashboard")


# -----------------------------
# Scan Button
# -----------------------------
if st.button("🔄 Scan Network"):

    df = scan_network()

    # Debugging
    st.write(df)

    st.success(f"✅ Total Devices Found: {len(df)}")

    # Empty DataFrame check
    if df.empty:

        st.warning("⚠️ No devices found on network")

    else:

        # Intruder detection
        intruders = df[
            ~df["MAC Address"].isin(trusted_devices)
        ]

        # Show intruder alerts
        if len(intruders) > 0:

            st.error("🚨 Intruder Devices Detected!")

            st.dataframe(intruders)

        else:

            st.success("✅ No intruders detected")

        # Full device table
        st.subheader("📋 Connected Devices")

        st.dataframe(df)