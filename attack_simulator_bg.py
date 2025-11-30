"""
Attack simulator for dashboard - runs in background
Simulates various network attacks for demo purposes
"""
import subprocess
import time

def simulate_attack():
    """Run attack simulation in background"""
    router_ip = "192.168.1.1"
    
    # Port scan
    ports = [80, 443, 22, 3389, 8080, 3306]
    for port in ports:
        subprocess.run(
            ['powershell', '-Command', f'Test-NetConnection -ComputerName {router_ip} -Port {port} -WarningAction SilentlyContinue'],
            capture_output=True,
            timeout=2
        )
    
    # ICMP flood
    for _ in range(20):
        subprocess.run(['ping', router_ip, '-n', '1'], capture_output=True, timeout=1)
    
    # DNS queries
    targets = ['google.com', 'example.com', 'facebook.com']
    for target in targets:
        for _ in range(5):
            subprocess.run(['nslookup', target], capture_output=True, timeout=2)
    
    # HTTP requests
    for target in targets:
        try:
            subprocess.run(
                ['powershell', '-Command', f'Invoke-WebRequest -Uri https://{target} -UseBasicParsing -TimeoutSec 2'],
                capture_output=True,
                timeout=3
            )
        except:
            pass

if __name__ == '__main__':
    simulate_attack()
