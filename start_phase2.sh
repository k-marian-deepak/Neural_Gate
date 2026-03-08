#!/bin/bash

echo "=================================================="
echo "Neural-Gate Phase 2 PCAP Setup"
echo "=================================================="
echo ""

# Check if running as root or with capabilities
if [[ $EUID -ne 0 ]] && ! getcap .venv/bin/python3 | grep -q cap_net_raw; then
    echo "[!] Phase 2 requires elevated permissions for packet capture"
    echo ""
    echo "Choose an option:"
    echo "  1) Grant capabilities to Python (recommended)"
    echo "  2) Run with sudo (this script will use sudo)"
    echo "  3) Exit and run manually"
    echo ""
    read -p "Enter choice [1-3]: " choice
    
    case $choice in
        1)
            echo "[*] Granting capabilities to Python..."
            sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
            echo "[*] Capabilities granted!"
            ;;
        2)
            USE_SUDO=1
            ;;
        3)
            echo "Manual setup instructions:"
            echo "  sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3"
            echo "  OR"
            echo "  sudo -E uvicorn app.main:app --host 0.0.0.0 --port 8000"
            exit 0
            ;;
    esac
fi

# Check dependencies
echo "[*] Checking dependencies..."
source .venv/bin/activate
python -c "from scapy.all import sniff" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[!] Scapy not found. Installing..."
    pip install scapy pyshark -q
fi

# List available interfaces
echo ""
echo "[*] Available network interfaces:"
ip link show | grep -E '^[0-9]+:' | awk '{print "  - " $2}' | sed 's/://'
echo ""

# Get interface choice
read -p "Enter interface to capture on [lo]: " INTERFACE
INTERFACE=${INTERFACE:-lo}

# Get BPF filter
read -p "Enter BPF filter [tcp port 8000]: " BPF_FILTER
BPF_FILTER=${BPF_FILTER:-"tcp port 8000"}

# Ask about saving PCAP
read -p "Save PCAP files to disk? [y/N]: " SAVE_PCAP
if [[ "$SAVE_PCAP" =~ ^[Yy]$ ]]; then
    SAVE_ENABLED=true
    mkdir -p pcap_dumps
    echo "[*] PCAP files will be saved to: pcap_dumps/"
else
    SAVE_ENABLED=false
fi

# Create .env file
echo ""
echo "[*] Creating .env configuration..."
cat > .env << EOF
NG_ENABLE_PHASE2_PCAP=true
NG_PCAP_INTERFACE=$INTERFACE
NG_PCAP_FILTER="$BPF_FILTER"
NG_PCAP_SAVE_ENABLED=$SAVE_ENABLED
NG_PCAP_SAVE_PATH=pcap_dumps
NG_TARGET_SERVER=http://localhost:3001
NG_PROXY_PORT=8000
EOF

echo "[*] Configuration saved to .env"
echo ""
echo "=================================================="
echo "Starting Neural-Gate with Phase 2 PCAP"
echo "=================================================="
echo "  Interface: $INTERFACE"
echo "  BPF Filter: $BPF_FILTER"
echo "  Save PCAP: $SAVE_ENABLED"
echo "=================================================="
echo ""

# Start the server
if [ "$USE_SUDO" = "1" ]; then
    echo "[*] Starting with sudo..."
    sudo -E .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
else
    uvicorn app.main:app --host 0.0.0.0 --port 8000
fi
