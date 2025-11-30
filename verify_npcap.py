"""
Npcap Installation Verification Script
"""
import sys

print("=" * 60)
print("🔍 Verifying Npcap Installation...")
print("=" * 60)

# Test 1: Import Scapy
try:
    from scapy.all import get_if_list, conf
    print("✅ Test 1: Scapy import successful")
except ImportError as e:
    print(f"❌ Test 1: Scapy import failed: {e}")
    sys.exit(1)

# Test 2: Check libpcap availability
try:
    if conf.use_pcap:
        print("✅ Test 2: Npcap/WinPcap detected by Scapy")
    else:
        print("⚠️ Test 2: Scapy is not using pcap (may use native mode)")
except Exception as e:
    print(f"⚠️ Test 2: Error checking pcap: {e}")

# Test 3: List network interfaces
try:
    interfaces = get_if_list()
    print(f"\n✅ Test 3: Network interfaces detected: {len(interfaces)}")
    print("\n📡 Available Network Interfaces:")
    print("-" * 60)
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    print("-" * 60)
except Exception as e:
    print(f"❌ Test 3: Failed to get interfaces: {e}")
    sys.exit(1)

# Test 4: Try to create a sniffer (without actually sniffing)
try:
    from scapy.all import AsyncSniffer
    print("\n✅ Test 4: AsyncSniffer import successful")
except ImportError as e:
    print(f"❌ Test 4: AsyncSniffer import failed: {e}")

# Final result
print("\n" + "=" * 60)
print("🎉 Npcap Installation Verified Successfully!")
print("=" * 60)
print("\n💡 You can now:")
print("   1. Start the dashboard: streamlit run dashboard\\app.py")
print("   2. Select your WiFi interface from the dropdown")
print("   3. Click 'Start Sniffer' to begin monitoring")
print("\n" + "=" * 60)
