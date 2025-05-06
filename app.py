import streamlit as st
import subprocess
import os
import tempfile

st.title("Simple Network Intrusion Detection System (NIDS)")

st.sidebar.header("Configuration")

mode = st.sidebar.radio("Select Mode", ["Live Capture", "Read from PCAP"])

if mode == "Live Capture":
    interface = st.sidebar.text_input("Network Interface", "eth0")
else:
    pcap_file = st.sidebar.file_uploader("Upload PCAP File", type=["pcap"])

portscan_threshold = st.sidebar.number_input("Portscan Threshold", min_value=1, value=15)
ddos_threshold = st.sidebar.number_input("DDoS Threshold", min_value=1, value=100)
whitelist_ips = st.sidebar.text_area("Whitelist IPs (comma-separated)", "")

start_detection = st.sidebar.button("Start Detection")

if start_detection:
    cmd = ["python", "nids_corrected.py"]

    if mode == "Live Capture":
        cmd += ["-i", interface]
    else:
        if pcap_file:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmpfile:
                tmpfile.write(pcap_file.read())
                pcap_path = tmpfile.name
            cmd += ["-r", pcap_path]
        else:
            st.error("Please upload a PCAP file.")
            st.stop()

    cmd += ["-p", str(portscan_threshold), "-d", str(ddos_threshold)]

    if whitelist_ips:
        ips = whitelist_ips.replace("\n", ",").split(",")
        cmd += ["-w"] + [ip.strip() for ip in ips if ip.strip()]

    st.text(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        st.text_area("Detection Output", result.stdout, height=400)
    except subprocess.CalledProcessError as e:
        st.error("Error occurred during execution:")
        st.text(e.stderr)
