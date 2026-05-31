
# =====================================================
# IMPORTS
# =====================================================

import streamlit as st
import pandas as pd
import socket
import json
import requests
import os
import sys

from pathlib import Path
from datetime import datetime
#from utils.network_utils import get_network_range

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from dotenv import load_dotenv
from streamlit_autorefresh import st_autorefresh

from database.db import engine
from ai.detect_anomaly import detect_anomaly


# =====================================================
# LOAD ENVIRONMENT VARIABLES
# =====================================================

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")


# =====================================================
# TELEGRAM ALERT FUNCTION
# Sends security alerts to Telegram
# =====================================================


def send_telegram_alert(message):

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


# =====================================================
# AI DEVICE CLASSIFICATION
# =====================================================


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


# =====================================================
# NETWORK SCANNER
# =====================================================


def scan_network():

    target_ip = "192.168.0.1/24"
    #target_ip = "192.168.1.1/24"
    #target_ip = get_network_range()

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=8, verbose=0)[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc.lower()

        # -----------------------------
        # Hostname Lookup
        # -----------------------------
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        # -----------------------------
        # Vendor Lookup
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


# =====================================================
# SAVE DATA INTO POSTGRESQL
# =====================================================


def save_to_database(df, trusted_devices):

    if df.empty:
        return

    records = []

    for _, row in df.iterrows():

        is_intruder = (
            row["MAC Address"] not in trusted_devices
        )

        records.append({

            "ip_address": row["IP Address"],

            "mac_address": row["MAC Address"],

            "hostname": row["Hostname"],

            "vendor": row["Vendor"],

            "device_type": row["Device Type"],

            "is_intruder": is_intruder,

            # Scan timestamp
            "scan_time": datetime.now()

        })

    save_df = pd.DataFrame(records)

    save_df.to_sql(
        "device_logs",
        engine,
        if_exists="append",
        index=False
    )


# =====================================================
# LOAD TRUSTED DEVICES
# =====================================================

with open("scanner/trusted_devices.json", "r") as file:
    trusted_devices = json.load(file)


# =====================================================
# STREAMLIT PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="AI Network Watcher",
    layout="wide"
)

st.title("📡 AI Network Watcher")

st.markdown(
    "### 🚀 Real-Time AI-Powered Wi-Fi Monitoring Dashboard"
)


# =====================================================
# AUTO REFRESH
# =====================================================

auto_refresh = st.checkbox(
    "Enable Auto Refresh (2 min)"
)

if auto_refresh:

    st_autorefresh(
        interval=120000,
        key="network_monitor"
    )


# =====================================================
# SCAN BUTTON
# =====================================================

scan_now = st.button("🔄 Scan Network")


# =====================================================
# MAIN EXECUTION
# =====================================================

if scan_now or auto_refresh:

    # -----------------------------
    # Scan Network
    # -----------------------------
    df = scan_network()

    st.success(f"✅ Total Devices Found: {len(df)}")

    # -----------------------------
    # Save Into PostgreSQL
    # -----------------------------
    save_to_database(df, trusted_devices)

    # -----------------------------
    # Empty Check
    # -----------------------------
    if df.empty:

        st.warning("⚠️ No devices found on network")

    else:

        # -----------------------------
        # Detect Intruders
        # -----------------------------
        intruders = df[
            ~df["MAC Address"].isin(trusted_devices)
        ]

        # -----------------------------
        # Intruder Detection
        # -----------------------------
        if len(intruders) > 0:

            st.error("🚨 Intruder Devices Detected!")

            st.dataframe(intruders)

            # -----------------------------
            # Process Each Intruder
            # -----------------------------
            for _, row in intruders.iterrows():

                # =====================================================
                # AI ANOMALY DETECTION
                # =====================================================

                ai_result = detect_anomaly(

                    scan_hour=datetime.now().hour,

                    vendor=row["Vendor"],

                    device_type=row["Device Type"],

                    is_intruder=True
                )

                # -----------------------------
                # Show AI Results
                # -----------------------------
                st.warning(
                    f"🧠 AI Anomaly Score: {ai_result['score']:.4f}"
                )

                # -----------------------------
                # AI Suspicious Detection
                # -----------------------------
                if ai_result["anomaly"]:

                    st.error(
                        "🚨 AI DETECTED SUSPICIOUS DEVICE"
                    )

                # -----------------------------
                # Telegram Alert Message
                # -----------------------------
                message = (
                    f"🚨 AI Security Alert!\n\n"
                    f"IP Address: {row['IP Address']}\n"
                    f"MAC Address: {row['MAC Address']}\n"
                    f"Vendor: {row['Vendor']}\n"
                    f"Device Type: {row['Device Type']}\n"
                    f"AI Anomaly Score: {ai_result['score']:.4f}\n"
                    f"Suspicious: {ai_result['anomaly']}"
                )

                # -----------------------------
                # Send Telegram Alert
                # -----------------------------
                send_telegram_alert(message)

        else:

            st.success("✅ No intruders detected")

        # -----------------------------
        # Show Connected Devices
        # -----------------------------
        st.subheader("📋 Connected Devices")

        st.dataframe(df)

