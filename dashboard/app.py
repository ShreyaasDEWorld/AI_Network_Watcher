import streamlit as st
import pandas as pd
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
            "IP Address": received.psrc,
            "MAC Address": received.hwsrc
        })

    return pd.DataFrame(devices)


st.set_page_config(
    page_title="AI Network Watcher",
    layout="wide"
)

st.title("📡 AI Network Watcher")

st.write("Real-time Wi-Fi device scanner")

if st.button("🔄 Scan Network"):
    df = scan_network()

    st.success(f"Found {len(df)} devices")

    st.dataframe(df)