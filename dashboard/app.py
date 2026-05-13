import streamlit as st
import pandas as pd
import socket
import json
import requests
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
import os


# -----------------------------
# Load Environment Variables
# -----------------------------
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")


# -----------------------------
# Telegram Alert Function
# -----------------------------
def send_telegram_alert(message):

    # Skip if credentials missing
    if not BOT_TOKEN or not CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:
        requests.post(url, data=payload)

    except Exception as e:
        st.error(f"Telegram Error: {e}")


# -----------------------------
# Scan Network
# -----------------------------
def scan_network():

    target_ip = "192.168.0.1/24"

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    # Increased timeout for better detection
    result = srp(packet, timeout=8, verbose=0)[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc.lower()

        # -----------------------------
        # Hostname lookup
        # -----------------------------
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # -----------------------------
        # Vendor lookup
        # -----------------------------
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown Vendor"

        # -----------------------------
        # AI Device Classification
        # -----------------------------
        device_type = classify_device(hostname, vendor)

        devices.append({
            "IP Address": ip,
            "MAC Address": mac,
            "Hostname": hostname,
            "Vendor": vendor,
            "Device Type": device_type
        })

    # -----------------------------
    # Debugging Output
    # -----------------------------
    st.write("Devices Raw Output:", devices)

    # -----------------------------
    # Return DataFrame
    # -----------------------------
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

st.markdown("### 🚀 Real-Time Wi-Fi Monitoring Dashboard")


# -----------------------------
# Scan Button
# -----------------------------
if st.button("🔄 Scan Network"):

    df = scan_network()

    st.success(f"✅ Total Devices Found: {len(df)}")

    # -----------------------------
    # Empty DataFrame Check
    # -----------------------------
    if df.empty:

        st.warning("⚠️ No devices found on network")

    else:

        # -----------------------------
        # Intruder Detection
        # -----------------------------
        intruders = df[
            ~df["MAC Address"].isin(trusted_devices)
        ]

        # -----------------------------
        # Show Intruder Alerts
        # -----------------------------
        if len(intruders) > 0:

            st.error("🚨 Intruder Devices Detected!")

            st.dataframe(intruders)

            # -----------------------------
            # Send Telegram Alerts
            # -----------------------------
            for _, row in intruders.iterrows():

                message = (
                    f"🚨 Intruder Detected!\n"
                    f"IP Address: {row['IP Address']}\n"
                    f"MAC Address: {row['MAC Address']}\n"
                    f"Vendor: {row['Vendor']}\n"
                    f"Device Type: {row['Device Type']}"
                )

                send_telegram_alert(message)

        else:

            st.success("✅ No intruders detected")

        # -----------------------------
        # Full Device Table
        # -----------------------------
        st.subheader("📋 Connected Devices")

        st.dataframe(df)