"""
Find the correct Wi-Fi interface device name
"""
from scapy.all import get_if_list, IFACES, conf
import subprocess

def get_active_wifi_ip():
    """Get IP address of active Wi-Fi adapter"""
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
        lines = result.stdout.split('\n')
        
        in_wifi = False
        for line in lines:
            if 'Wireless LAN adapter Wi-Fi:' in line:
                in_wifi = True
            elif in_wifi and 'IPv4 Address' in line:
                # Extract IP
                ip = line.split(':')[-1].strip()
                return ip
            elif in_wifi and 'adapter' in line.lower():
                in_wifi = False
    except:
        pass
    return None

def find_wifi_device():
    """Map device names to friendly names and find Wi-Fi"""
    print("\n" + "="*80)
    print("🔍 Searching for Wi-Fi Interface...")
    print("="*80)
    
    wifi_ip = get_active_wifi_ip()
    print(f"\n✅ Your Wi-Fi IP: {wifi_ip}")
    print(f"✅ Network: SadiaSultana\n")
    
    all_ifaces = get_if_list()
    
    print(f"📡 Found {len(all_ifaces)} network interfaces:\n")
    
    wifi_device = None
    
    for idx, iface in enumerate(all_ifaces, 1):
        # Try to get friendly name
        try:
            if hasattr(IFACES, 'dev_from_name'):
                iface_obj = IFACES.dev_from_name(iface)
                description = getattr(iface_obj, 'description', 'N/A')
                ip = getattr(iface_obj, 'ip', 'N/A')
                
                # Check if this is Wi-Fi
                is_wifi = False
                if wifi_ip and str(ip) == wifi_ip:
                    is_wifi = True
                    wifi_device = iface
                elif 'wi-fi' in description.lower() or 'wireless' in description.lower():
                    if 'disconnected' not in description.lower():
                        is_wifi = True
                        wifi_device = iface
                
                marker = "🎯 ← YOUR Wi-Fi (SadiaSultana)" if is_wifi else ""
                
                print(f"{idx}. Device: {iface}")
                print(f"   Description: {description}")
                print(f"   IP: {ip} {marker}")
                print()
            else:
                print(f"{idx}. {iface}")
                print()
        except Exception as e:
            print(f"{idx}. {iface} (error: {e})")
            print()
    
    print("="*80)
    if wifi_device:
        print(f"\n✅ FOUND YOUR Wi-Fi INTERFACE!")
        print(f"   Device: {wifi_device}")
        print(f"\n📋 Dashboard এ এই device টি select করো:\n   {wifi_device}\n")
    else:
        print("\n⚠️  Could not auto-detect Wi-Fi interface.")
        print("💡 Try each interface one by one in the dashboard.")
        print("   The one with IP 192.168.1.7 is your Wi-Fi.\n")
    print("="*80)

if __name__ == '__main__':
    find_wifi_device()
