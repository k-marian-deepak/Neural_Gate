#!/usr/bin/env python3
"""
Quick verification script for Phase 2 PCAP functionality
"""
import os
import sys

def check_dependencies():
    """Check if all required packages are installed"""
    print("[*] Checking dependencies...")
    
    try:
        import scapy.all
        print("  ✓ scapy installed")
    except ImportError:
        print("  ✗ scapy NOT installed - run: pip install scapy")
        return False
    
    try:
        import pyshark
        print("  ✓ pyshark installed")
    except ImportError:
        print("  ✗ pyshark NOT installed - run: pip install pyshark")
        return False
    
    return True

def check_permissions():
    """Check if we have permission to capture packets"""
    print("\n[*] Checking packet capture permissions...")
    
    # Method 1: Check if running as root
    if os.geteuid() == 0:
        print("  ✓ Running as root")
        return True
    
    # Method 2: Check if Python has capabilities
    import subprocess
    try:
        python_path = sys.executable
        result = subprocess.run(['getcap', python_path], capture_output=True, text=True)
        
        if 'cap_net_raw' in result.stdout and 'cap_net_admin' in result.stdout:
            print(f"  ✓ Python has capabilities: {result.stdout.strip()}")
            return True
        else:
            print(f"  ✗ Python lacks capabilities")
            print(f"\n  To fix, run:")
            print(f"    sudo setcap cap_net_raw,cap_net_admin=eip {python_path}")
            return False
    except FileNotFoundError:
        print("  ⚠ getcap not found, cannot verify capabilities")
        return None

def check_configuration():
    """Check Phase 2 configuration"""
    print("\n[*] Checking configuration...")
    
    from app.config import get_settings
    settings = get_settings()
    
    print(f"  Phase 2 Enabled: {settings.enable_phase2_pcap}")
    print(f"  PCAP Interface: {settings.pcap_interface}")
    print(f"  PCAP Filter: {settings.pcap_filter}")
    print(f"  Save PCAP: {settings.pcap_save_enabled}")
    if settings.pcap_save_enabled:
        print(f"  Save Path: {settings.pcap_save_path}")
    
    return settings.enable_phase2_pcap

def test_packet_capture():
    """Test if we can actually capture packets"""
    print("\n[*] Testing packet capture...")
    
    try:
        from scapy.all import sniff
        print("  Attempting to capture 1 packet (3 second timeout)...")
        
        packets = sniff(count=1, timeout=3, iface="lo")
        
        if packets:
            print(f"  ✓ Successfully captured {len(packets)} packet(s)")
            return True
        else:
            print("  ⚠ No packets captured (may need to generate traffic)")
            return True  # Still counts as success if no permission errors
            
    except PermissionError:
        print("  ✗ Permission denied - need root or capabilities")
        return False
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def main():
    print("=" * 60)
    print("Neural-Gate Phase 2 PCAP Verification")
    print("=" * 60)
    
    deps_ok = check_dependencies()
    if not deps_ok:
        print("\n[!] Dependency check failed")
        return 1
    
    perms_ok = check_permissions()
    if perms_ok is False:
        print("\n[!] Permission check failed")
        print("[!] You can still run Neural-Gate with sudo, or fix permissions")
    
    config_ok = check_configuration()
    if not config_ok:
        print("\n[!] Phase 2 not enabled in configuration")
        print("    Set NG_ENABLE_PHASE2_PCAP=true in .env or environment")
    
    if perms_ok:
        capture_ok = test_packet_capture()
        if not capture_ok:
            print("\n[!] Packet capture test failed")
            return 1
    
    print("\n" + "=" * 60)
    if deps_ok and (perms_ok or perms_ok is None) and config_ok:
        print("✓ Phase 2 verification PASSED")
        print("\nYou are ready to run Neural-Gate with Phase 2 PCAP!")
        print("Start with: ./start_phase2.sh")
        return 0
    else:
        print("⚠ Phase 2 verification INCOMPLETE")
        print("\nReview the issues above before starting Phase 2")
        return 1

if __name__ == "__main__":
    sys.exit(main())
