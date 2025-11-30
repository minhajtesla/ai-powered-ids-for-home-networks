"""
Enhanced sniffer with interface auto-detection
Tries multiple interfaces to find the active one
"""
import scapy.all as scapy
import pandas as pd
import os
import sys
import subprocess
from datetime import datetime
import time

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')

features = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length'
]

packet_count = 0

def extract_features(packet):
    if not packet.haslayer(scapy.IP):
        return None
    ip_layer = packet[scapy.IP]
    proto = ip_layer.proto
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
    src_port = dst_port = None
    if protocol == 'TCP' and packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif protocol == 'UDP' and packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
    return {
        'timestamp': datetime.now().isoformat(),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'packet_length': len(packet)
    }

def packet_callback(packet):
    global packet_count
    feat = extract_features(packet)
    if feat:
        df = pd.DataFrame([feat])
        if not os.path.exists(DATA_PATH):
            df.to_csv(DATA_PATH, index=False, mode='w', header=True)
        else:
            df.to_csv(DATA_PATH, index=False, mode='a', header=False)
        packet_count += 1
        print(f"[{packet_count}] {feat['protocol']:5} {feat['src_ip']:15}  {feat['dst_ip']:15} ({feat['packet_length']} bytes)")

def get_wifi_ip():
    """Get Wi-Fi IP from ipconfig"""
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
        lines = result.stdout.split('\n')
        in_wifi = False
        for line in lines:
            if 'Wireless LAN adapter Wi-Fi:' in line:
                in_wifi = True
            elif in_wifi and 'IPv4 Address' in line:
                ip = line.split(':')[-1].strip().replace('(Preferred)', '').strip()
                return ip
            elif in_wifi and 'adapter' in line.lower():
                in_wifi = False
    except:
        pass
    return None

def get_wifi_network_name():
    """Get current Wi-Fi network SSID from netsh or IP-based detection"""
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                              capture_output=True, text=True, shell=True)
        for line in result.stdout.split('\n'):
            if 'SSID' in line and 'BSSID' not in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    ssid = parts[1].strip()
                    if ssid:
                        return ssid
    except:
        pass
    
    # Fallback: detect by IP range
    wifi_ip = get_wifi_ip()
    if wifi_ip:
        if wifi_ip.startswith('192.168.1.'):
            return "SadiaSultana"
        elif wifi_ip.startswith('10.19.32.'):
            return "Previous Network (10.19.32.x)"
    
    return "Unknown Network"

if __name__ == '__main__':
    from scapy.all import get_if_list
    
    # Clear old data files for fresh session
    LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')
    if os.path.exists(DATA_PATH):
        os.remove(DATA_PATH)
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    
    print('=' * 80)
    print('🛡️ AI-Powered IDS - Smart Network Packet Sniffer')
    print('=' * 80)
    print('✅ Old data cleared - starting fresh session')
    
    wifi_ip = get_wifi_ip()
    wifi_network = get_wifi_network_name()
    
    if wifi_ip:
        print(f'\n Your Wi-Fi IP: {wifi_ip}')
    else:
        print(f'\n  Wi-Fi IP: Not detected (may be on Ethernet or VPN)')
    print(f' Network: {wifi_network}')
    
    # List available interfaces
    interfaces = get_if_list()
    real_ifaces = [i for i in interfaces if 'Loopback' not in i]
    
    print(f'\n Found {len(real_ifaces)} network interfaces (excluding loopback)')
    
    # Check if interface specified via command line
    selected_iface = None
    if len(sys.argv) > 1:
        try:
            idx = int(sys.argv[1]) - 1
            selected_iface = real_ifaces[idx]
            print(f'\n Using interface #{sys.argv[1]}: {selected_iface}')
        except:
            print(f'\n Invalid interface number, using auto-detect')
    
    if not selected_iface:
        print('\n Auto-selecting first active interface...')
        print('   (If no packets appear, dashboard will try other interfaces)\n')
        selected_iface = real_ifaces[0] if real_ifaces else None
    
    if not selected_iface:
        print(' No network interfaces found!')
        input('\nPress Enter to close...')
        sys.exit(1)
    
    print(f'\n Selected: {selected_iface}')
    print(f' Saving to: {DATA_PATH}')
    print('\n Starting packet capture...')
    print(' Generate traffic (browse web, ping, etc.) to see packets')
    print(' Press Ctrl+C to stop\n')
    print('=' * 80)
    
    try:
        # Try sniffing on selected interface
        scapy.sniff(iface=selected_iface, prn=packet_callback, store=0, promisc=True)
    except KeyboardInterrupt:
        print('\n\n' + '=' * 80)
        print(f' Packet capture stopped! Total packets: {packet_count}')
        print(f' Data saved to: {DATA_PATH}')
        print('=' * 80)
    except Exception as e:
        print(f'\n Error on interface {selected_iface}: {e}')
        print('\n Trying fallback mode (all interfaces)...\n')
        try:
            scapy.sniff(prn=packet_callback, store=0, promisc=True)
        except KeyboardInterrupt:
            print(f'\n Stopped! Total packets: {packet_count}')
        except Exception as e2:
            print(f' Fallback failed: {e2}')
            print('\n Solutions:')
            print('   1. Run as Administrator')
            print('   2. Verify Npcap is installed')
            print('   3. Try different interface from dashboard')
            input('\nPress Enter to close...')
