import streamlit as st
import pandas as pd
import os
import time
from datetime import datetime
from collections import defaultdict
import subprocess
import sys

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

st.set_page_config(page_title='🛡️ WiFi Network Monitor | AI-Powered IDS', layout='wide', initial_sidebar_state='expanded')

# Header with status
col_header1, col_header2 = st.columns([3, 1])
with col_header1:
    st.title('🛡️ AI-Powered IDS - WiFi Network Monitor')
    st.caption('Real-time network traffic monitoring and threat detection')
with col_header2:
    st.metric("System Status", "🟢 Online", delta="Active")

# Sidebar Controls
st.sidebar.header('⚙️ Configuration')

# Network Interface Selection
try:
    from scapy.all import get_if_list
    interfaces = get_if_list()
    # Filter out loopback
    real_interfaces = [i for i in interfaces if 'Loopback' not in i]
    
    # Create interface options with index
    interface_options = {f"Interface #{idx+1}": iface for idx, iface in enumerate(real_interfaces)}
    
    selected_interface_label = st.sidebar.selectbox(
        '📡 Network Interface',
        list(interface_options.keys()),
        help='Select interface number to try. Start with #1, if no packets try #2, #3, etc.'
    )
    selected_interface = interface_options[selected_interface_label]
    selected_interface_index = int(selected_interface_label.split('#')[1])
    
    st.sidebar.info(f'Will use: {selected_interface_label}')
except Exception as e:
    st.sidebar.error(f'Error loading interfaces: {e}')
    selected_interface = None
    selected_interface_index = 1

# Packet Count
packet_count = st.sidebar.number_input(
    '📦 Packet Count',
    min_value=-1,
    value=100,
    help='Number of packets to capture (-1 for unlimited monitoring)'
)

# AbuseIPDB API Key
api_key = st.sidebar.text_input(
    '🔑 AbuseIPDB API Key (Optional)',
    type='password',
    help='Get free API key from https://www.abuseipdb.com/'
)

# Control Buttons
st.sidebar.markdown('---')
st.sidebar.header('🎮 Controls')

col_btn1, col_btn2 = st.sidebar.columns(2)
with col_btn1:
    if st.button('🟢 Start Sniffer', use_container_width=True):
        st.sidebar.info('Starting packet capture...')
        try:
            project_dir = os.path.dirname(os.path.dirname(__file__))
            python_exe = os.path.join(project_dir, 'venv', 'Scripts', 'python.exe')
            sniffer_script = os.path.join(project_dir, 'src', 'sniffer_smart.py')
            # Pass interface index as argument
            cmd = f'start cmd /k ""{python_exe}" "{sniffer_script}" {selected_interface_index}""'
            subprocess.Popen(cmd, shell=True)
            st.sidebar.success(f'Sniffer started with {selected_interface_label}!')
        except Exception as e:
            st.sidebar.error(f'Error: {e}')

with col_btn2:
    if st.button('🔴 Stop Monitor', use_container_width=True):
        st.sidebar.warning('Stop sniffer manually (Ctrl+C in sniffer window)')

# Detection Toggle
enable_detection = st.sidebar.checkbox(
    '☑️ Enable Real-time Detection',
    value=True,
    help='Use ML model to detect threats in real-time'
)

if enable_detection:
    if st.sidebar.button('▶️ Start Detection', use_container_width=True):
        st.sidebar.info('Starting real-time detection...')
        try:
            project_dir = os.path.dirname(os.path.dirname(__file__))
            python_exe = os.path.join(project_dir, 'venv', 'Scripts', 'python.exe')
            detect_script = os.path.join(project_dir, 'src', 'realtime_detect.py')
            cmd = f'start cmd /k ""{python_exe}" "{detect_script}""'
            subprocess.Popen(cmd, shell=True)
            st.sidebar.success('Detection started in new window!')
        except Exception as e:
            st.sidebar.error(f'Error: {e}')

st.sidebar.markdown('---')

# Data Tools: Clear captured data and alerts
st.sidebar.header('🧹 Data Tools')
if st.sidebar.button('Clear All Data', use_container_width=True):
    try:
        removed = []
        if os.path.exists(DATA_PATH):
            os.remove(DATA_PATH)
            removed.append('packets')
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
            removed.append('alerts')
        if removed:
            st.sidebar.success(f"Cleared: {', '.join(removed)}. Dashboard will refresh.")
        else:
            st.sidebar.info('Nothing to clear. No data files found.')
        time.sleep(0.5)
        st.rerun()
    except Exception as e:
        st.sidebar.error(f'Error clearing data: {e}')

# Attack Simulation (for demo)
st.sidebar.markdown('---')
st.sidebar.header('🎯 Demo Tools')
st.sidebar.caption('Simulate network attacks for demonstration')

if st.sidebar.button('⚡ Simulate Attack', use_container_width=True):
    st.sidebar.warning('Starting attack simulation...')
    try:
        project_dir = os.path.dirname(os.path.dirname(__file__))
        python_exe = os.path.join(project_dir, 'venv', 'Scripts', 'python.exe')
        attack_script = os.path.join(project_dir, 'attack_simulator_bg.py')
        # Run in background
        subprocess.Popen([python_exe, attack_script], 
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        st.sidebar.success('✅ Attack simulation running! Watch dashboard metrics update.')
        time.sleep(1)
        st.rerun()
    except Exception as e:
        st.sidebar.error(f'Error: {e}')

# Live traffic stats
def load_packets():
    if os.path.exists(DATA_PATH):
        try:
            # Robust CSV read: skip bad/partial lines due to concurrent writes
            df = pd.read_csv(
                DATA_PATH,
                engine='python',
                on_bad_lines='skip'
            )
            # Ensure expected columns exist
            expected = ['timestamp','src_ip','dst_ip','src_port','dst_port','protocol','packet_length']
            for col in expected:
                if col not in df.columns:
                    df[col] = None
            return df
        except Exception as e:
            # Fallback: try reading last N lines manually to avoid parser errors
            try:
                import csv
                rows = []
                with open(DATA_PATH, encoding='utf-8', errors='ignore') as f:
                    for row in csv.reader(f):
                        if len(row) >= 7:
                            rows.append(row[:7])
                if rows:
                    df = pd.DataFrame(rows[-500:], columns=['timestamp','src_ip','dst_ip','src_port','dst_port','protocol','packet_length'])
                    return df
            except Exception:
                pass
            return pd.DataFrame()
    return pd.DataFrame()

def load_alerts():
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            return lines[-20:][::-1]  # Show last 20 alerts, newest first
        except Exception:
            return []
    return []

# Auto-refresh
auto_refresh = st.sidebar.checkbox('🔄 Auto-refresh (every 5s)', value=False)
if auto_refresh:
    time.sleep(5)
    st.rerun()

# Load data
packets = load_packets()
alerts = load_alerts()

# Network Statistics Dashboard
st.header('📊 Network Statistics')

# Calculate stats
total_packets = len(packets)
alert_count = len(alerts)
normal_count = total_packets - alert_count

# Get unique devices (union of src/dst IPs)
if not packets.empty and 'src_ip' in packets.columns and 'dst_ip' in packets.columns:
    try:
        unique_devices = len(set(packets['src_ip'].dropna()) | set(packets['dst_ip'].dropna()))
    except Exception:
        unique_devices = 0
else:
    unique_devices = 0

# Protocol distribution
protocol_counts = packets['protocol'].value_counts().to_dict() if not packets.empty else {}

# Metrics
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric('📦 Total Packets', f'{total_packets:,}')
with col2:
    st.metric('✅ Normal Traffic', f'{normal_count:,}', delta='Safe')
with col3:
    st.metric('⚠️ Alerts', alert_count, delta='-' if alert_count > 0 else 'Good')
with col4:
    st.metric('🌐 Unique Devices', unique_devices)
with col5:
    detection_rate = round((normal_count / total_packets * 100), 2) if total_packets > 0 else 100
    st.metric('🎯 Detection Rate', f'{detection_rate}%')

st.markdown('---')

# Connected Devices Table
st.header('🖥️ Connected Devices')

if not packets.empty:
    # Group by source IP
    device_stats = packets.groupby('src_ip').agg({
        'packet_length': ['count', 'sum', 'mean'],
        'protocol': lambda x: ', '.join([str(p) for p in x.unique()[:3] if pd.notnull(p)]),
        'dst_ip': 'nunique'
    }).reset_index()
    
    device_stats.columns = ['IP Address', 'Packets', 'Total Bytes', 'Avg Size', 'Protocols', 'Connections']
    device_stats = device_stats.sort_values('Packets', ascending=False)
    
    # Add status based on alerts
    def get_status(ip):
        for alert in alerts:
            if ip in alert:
                if 'ATTACK' in alert or 'Port Scan' in alert or 'DDoS' in alert:
                    return '🚨 Threat'
                elif 'SUSPICIOUS' in alert:
                    return '⚠️ Suspicious'
        return '✅ Normal'
    
    device_stats['Status'] = device_stats['IP Address'].apply(get_status)
    
    # Display table with color coding
    st.dataframe(
        device_stats,
        use_container_width=True,
        height=300,
        hide_index=True
    )
    
    # Protocol Distribution Chart
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        st.subheader('📡 Protocol Distribution')
        if protocol_counts:
            protocol_df = pd.DataFrame(list(protocol_counts.items()), columns=['Protocol', 'Count'])
            st.bar_chart(protocol_df.set_index('Protocol'))
        else:
            st.info('No data yet')
    
    with col_chart2:
        st.subheader('📈 Traffic Over Time')
        if len(packets) > 1:
            packets_recent = packets.tail(100).copy()
            packets_recent['idx'] = range(len(packets_recent))
            st.line_chart(packets_recent.set_index('idx')['packet_length'])
        else:
            st.info('Collecting data...')
else:
    st.info('⏳ Waiting for packet capture to start...\n\nClick **"🟢 Start Sniffer"** in the sidebar to begin monitoring.')

st.markdown('---')

# Threat Alerts Section
col_alert1, col_alert2 = st.columns([2, 1])

with col_alert1:
    st.header('🚨 Recent Threat Alerts')
    if alerts:
        for i, alert in enumerate(alerts[:10]):
            if 'ATTACK' in alert or 'SUSPICIOUS' in alert:
                st.error(f'**Alert #{i+1}:** {alert.strip()}')
            elif 'BLOCKED' in alert:
                st.warning(f'**Alert #{i+1}:** {alert.strip()}')
            else:
                st.info(f'**Alert #{i+1}:** {alert.strip()}')
    else:
        st.success('✅ No threats detected. Your network is secure!')

with col_alert2:
    st.header('📋 Latest Packets')
    if not packets.empty:
        recent_packets = packets.tail(10)[['src_ip', 'dst_ip', 'protocol', 'packet_length']]
        st.dataframe(recent_packets, use_container_width=True, hide_index=True)
    else:
        st.info('No packets captured yet')

st.markdown('---')

st.markdown('---')

# Sidebar: Threat Intelligence (AbuseIPDB)
st.sidebar.header('🔍 Threat Intelligence')
last_abuse = None
for line in alerts:
    if 'AbuseIPDB:' in line:
        try:
            import ast
            abuse_data = ast.literal_eval(line.split('AbuseIPDB:')[1].strip())
            last_abuse = abuse_data
            break
        except Exception:
            continue

if last_abuse:
    st.sidebar.markdown('**Latest IP Reputation Check:**')
    st.sidebar.write(f"🌍 **IP:** {last_abuse.get('ip', 'N/A')}")
    score = last_abuse.get('abuseConfidenceScore', 0)
    if score >= 75:
        st.sidebar.error(f"⚠️ **Abuse Score:** {score}% (HIGH RISK)")
    elif score >= 25:
        st.sidebar.warning(f"⚠️ **Abuse Score:** {score}% (MEDIUM)")
    else:
        st.sidebar.success(f"✅ **Abuse Score:** {score}% (LOW)")
    
    st.sidebar.write(f"🌐 **Country:** {last_abuse.get('countryCode', 'Unknown')}")
    st.sidebar.write(f"🏢 **Usage:** {last_abuse.get('usageType', 'Unknown')}")
    st.sidebar.write(f"📊 **Total Reports:** {last_abuse.get('totalReports', 0)}")
    
    if score >= 50:
        st.sidebar.error('🚫 This IP was auto-blocked!')
else:
    st.sidebar.info('No recent threat intelligence data')

# Footer
st.markdown('---')
st.caption('🛡️ AI-Powered IDS for Home Networks | Built with Streamlit & Scapy | Dashboard v2.0')
st.caption('💡 **Tip:** Enable auto-refresh to see live updates every 5 seconds') 