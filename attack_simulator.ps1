# AI-Powered IDS - Attack Simulator for Demo
# This script simulates various network attacks for demonstration purposes

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " AI-Powered IDS - Attack Simulator" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This script simulates suspicious network activity for DEMO purposes only." -ForegroundColor Red
Write-Host "Use only on networks you own or have permission to test." -ForegroundColor Red
Write-Host ""

# Get router IP
$routerIP = "192.168.1.1"
$externalTargets = @("example.com", "httpbin.org", "google.com")

Write-Host "[1/5] Starting Port Scan Simulation..." -ForegroundColor Green
Write-Host "       Scanning common ports on $routerIP" -ForegroundColor Gray

# Port scan simulation (common ports)
$ports = @(21, 22, 23, 25, 80, 443, 3389, 8080, 3306, 5432, 27017)
foreach ($port in $ports) {
    Test-NetConnection -ComputerName $routerIP -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet | Out-Null
    Write-Host "       Scanning port $port..." -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 200
}

Write-Host ""
Write-Host "[2/5] ICMP Flood Simulation..." -ForegroundColor Green
Write-Host "       Sending rapid ping requests" -ForegroundColor Gray

# ICMP flood (benign)
1..20 | ForEach-Object {
    ping $routerIP -n 1 | Out-Null
    Write-Host "       ICMP packet $_/20" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[3/5] DNS Query Flood..." -ForegroundColor Green
Write-Host "       Multiple DNS lookups" -ForegroundColor Gray

# DNS queries
foreach ($target in $externalTargets) {
    1..5 | ForEach-Object {
        nslookup $target 2>&1 | Out-Null
        Write-Host "       DNS query: $target" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "[4/5] HTTP Request Flood..." -ForegroundColor Green
Write-Host "       Rapid HTTP requests to multiple endpoints" -ForegroundColor Gray

# HTTP flood
foreach ($target in $externalTargets) {
    try {
        1..3 | ForEach-Object {
            Invoke-WebRequest -Uri "https://$target" -UseBasicParsing -TimeoutSec 2 2>&1 | Out-Null
            Write-Host "       HTTP request to $target" -ForegroundColor DarkGray
        }
    } catch {
        # Ignore errors
    }
}

Write-Host ""
Write-Host "[5/5] Suspicious Traffic Pattern..." -ForegroundColor Green
Write-Host "       Mixed protocol activity" -ForegroundColor Gray

# Mixed traffic
1..10 | ForEach-Object {
    # Random activities
    ping $routerIP -n 1 | Out-Null
    nslookup google.com 2>&1 | Out-Null
    Test-NetConnection -ComputerName $routerIP -Port 80 -WarningAction SilentlyContinue -InformationLevel Quiet | Out-Null
    Write-Host "       Mixed activity batch $_/10" -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 300
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Attack Simulation Complete!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Check your IDS Dashboard now:" -ForegroundColor Yellow
Write-Host "  - Total Packets should have increased significantly" -ForegroundColor White
Write-Host "  - Alerts section should show suspicious activity" -ForegroundColor White
Write-Host "  - Protocol Distribution should show mixed traffic" -ForegroundColor White
Write-Host "  - Connected Devices should show your IP with high packet count" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
