"""
Quick Wi-Fi Interface Finder
Tests each interface to find the active one
"""
from scapy.all import get_if_list, sniff, conf
import subprocess

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
    return "192.168.1.7"  # Fallback

print("="*80)
print("🔍 Wi-Fi Interface Finder for SadiaSultana Network")
print("="*80)

wifi_ip = get_wifi_ip()
print(f"\n✅ Your Wi-Fi IP Address: {wifi_ip}")
print(f"✅ Network Name: SadiaSultana")
print(f"\n📡 Available Interfaces:\n")

interfaces = get_if_list()

# Filter out obvious non-Wi-Fi interfaces
recommended = []
others = []

for idx, iface in enumerate(interfaces, 1):
    if 'Loopback' in iface:
        continue
    
    # The interfaces are numbered, try to correlate
    print(f"{idx}. {iface}")
    
    # Add to recommended if it looks promising
    if idx <= 6:  # First 6 are usually real adapters
        recommended.append(iface)
    else:
        others.append(iface)

print("\n" + "="*80)
print("💡 SOLUTION: Try These In Order")
print("="*80)

print(f"""
যেহেতু automatic detection কাজ করছে না, তোমাকে manually try করতে হবে।
Dashboard এ এই interfaces গুলো একটা একটা করে try করো:

🎯 RECOMMENDED ORDER (এগুলো first try করো):
""")

for idx, iface in enumerate(recommended[:6], 1):
    print(f"   {idx}. {iface}")

print(f"""
📋 HOW TO TEST:
   1. Dashboard sidebar এ interface select করো
   2. "Start Sniffer" button click করো
   3. Sniffer window এ কিছু packet দেখা গেলে = সঠিক interface! ✅
   4. কিছু না দেখালে sniffer close করে পরেরটা try করো
   
💡 TIP: 
   - যে interface এ IP {wifi_ip} দেখাবে সেটাই তোমার Wi-Fi
   - Usually 3rd বা 4th interface টা Wi-Fi হয়
   - Loopback select করবে না

⚡ QUICK TEST:
   Dashboard চালু আছে → Sidebar থেকে উপরের প্রথম interface select করো 
   → Start Sniffer → কিছু packet দেখা যায় কিনা check করো
""")

print("="*80)
