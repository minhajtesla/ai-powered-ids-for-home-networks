import scapy.all as scapy
import pandas as pd
import os
from datetime import datetime

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')

features = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length'
]

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
    feat = extract_features(packet)
    if feat:
        df = pd.DataFrame([feat])
        if not os.path.exists(DATA_PATH):
            df.to_csv(DATA_PATH, index=False, mode='w', header=True)
        else:
            df.to_csv(DATA_PATH, index=False, mode='a', header=False)
        print(feat)

if __name__ == '__main__':
    from scapy.all import get_if_list
    import sys
    
    print('=' * 70)
    print('🛡️ AI-Powered IDS - Network Packet Sniffer')
    print('=' * 70)
    
    # List available interfaces
    interfaces = get_if_list()
    print('\n📡 Available Network Interfaces:')
    for i, iface in enumerate(interfaces, 1):
        print(f'  {i}. {iface}')
    
    # Auto-detect or use all interfaces
    print('\n💡 Attempting to auto-detect active network interface...')
    
    try:
        # Try to sniff on all interfaces (works on some systems)
        iface = None
        
        # Filter out loopback
        real_ifaces = [i for i in interfaces if 'Loopback' not in i]
        
        if len(real_ifaces) > 0:
            # Try the first non-loopback interface
            iface = real_ifaces[0]
            
        if not iface:
            iface = interfaces[0] if interfaces else None
        
        if not iface:
            print('❌ No network interfaces found!')
            sys.exit(1)
        
        print(f'\n✅ Selected interface: {iface}')
        print(f'📊 Captured packets will be saved to: {DATA_PATH}')
        print('\n🔴 Starting packet capture... Press Ctrl+C to stop.')
        print('💡 If no packets appear, close this window and try a different interface from dashboard.')
        print('=' * 70)
        print()
        
        # Start sniffing with promiscuous mode
        # Use iface=None to sniff on all interfaces (Windows sometimes requires this)
        try:
            scapy.sniff(iface=iface, prn=packet_callback, store=0, promisc=True)
        except:
            # Fallback: try without specifying interface
            print(f'⚠️ Could not sniff on {iface}, trying all interfaces...')
            scapy.sniff(prn=packet_callback, store=0, promisc=True)
        
    except KeyboardInterrupt:
        print('\n\n' + '=' * 70)
        print('✅ Packet capture stopped!')
        print(f'📁 Data saved to: {DATA_PATH}')
        print('=' * 70)
    except Exception as e:
        print(f'\n❌ Error: {e}')
        print('💡 Try running as Administrator for full access to network interfaces')
        print('💡 Or try selecting a different interface from the dashboard')
        input('\nPress Enter to close...') 