"""
Helper script to get friendly network interface names
"""
from scapy.all import get_if_list, IFACES
import json

def get_friendly_interfaces():
    """Get network interfaces with friendly names for Windows"""
    interfaces = {}
    
    try:
        # Get all interfaces from scapy
        all_ifaces = get_if_list()
        
        # Try to get friendly names from IFACES
        for iface_name in all_ifaces:
            try:
                # Get interface object
                if hasattr(IFACES, 'dev_from_name'):
                    iface_obj = IFACES.dev_from_name(iface_name)
                    friendly_name = getattr(iface_obj, 'description', iface_name)
                    if not friendly_name or friendly_name == iface_name:
                        friendly_name = getattr(iface_obj, 'name', iface_name)
                else:
                    friendly_name = iface_name
                
                interfaces[iface_name] = {
                    'friendly_name': friendly_name,
                    'device': iface_name
                }
            except:
                interfaces[iface_name] = {
                    'friendly_name': iface_name,
                    'device': iface_name
                }
            
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        # Fallback to basic interface list
        for iface in get_if_list():
            interfaces[iface] = {
                'friendly_name': iface,
                'device': iface
            }
    
    return interfaces

if __name__ == '__main__':
    ifaces = get_friendly_interfaces()
    print("\n📡 Network Interfaces:")
    print("=" * 80)
    for device, info in ifaces.items():
        print(f"\nDevice: {device}")
        print(f"  Friendly Name: {info['friendly_name']}")
    print("=" * 80)
    print(f"\nTotal interfaces found: {len(ifaces)}")

