from __future__ import annotations

import math
import os
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings

# Optional PCAP dependencies
try:
    from scapy.all import sniff, wrpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    TCP = IP = Raw = None

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    distribution = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in distribution.values())


class PCAPEngine:
    """Phase 2: Real packet capture engine using Scapy"""
    
    def __init__(self):
        self.enabled = settings.enable_phase2_pcap and SCAPY_AVAILABLE
        self.interface = settings.pcap_interface
        self.filter = settings.pcap_filter
        self.packets = []
        self.capture_thread = None
        self.running = False
        self.save_enabled = settings.pcap_save_enabled
        self.save_path = Path(settings.pcap_save_path)
        
        if self.save_enabled:
            self.save_path.mkdir(parents=True, exist_ok=True)
    
    def start_capture(self):
        """Start background packet capture"""
        if not self.enabled:
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
    
    def _capture_loop(self):
        """Background packet capture loop"""
        while self.running:
            try:
                # Capture packets (count=10 per iteration, timeout=1s)
                pkts = sniff(
                    iface=self.interface,
                    filter=self.filter,
                    count=10,
                    timeout=1,
                    store=True
                )
                if pkts:
                    self.packets.extend(pkts)
                    
                    # Keep only last 1000 packets in memory
                    if len(self.packets) > 1000:
                        self.packets = self.packets[-1000:]
                    
                    # Save to file if enabled
                    if self.save_enabled:
                        self._save_packets(pkts)
            except Exception as e:
                print(f"[PCAP] Capture error: {e}")
                time.sleep(1)
    
    def _save_packets(self, packets):
        """Save captured packets to PCAP file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.save_path / f"capture_{timestamp}.pcap"
        try:
            wrpcap(str(filename), packets, append=True)
        except Exception as e:
            print(f"[PCAP] Save error: {e}")
    
    def stop_capture(self):
        """Stop background capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def extract_features_from_packet(self, packet) -> dict[str, Any]:
        """Extract features from raw packet"""
        features = {
            "phase": "pcap_raw",
            "packet_size": len(packet),
            "has_tcp": packet.haslayer(TCP) if TCP else False,
            "has_ip": packet.haslayer(IP) if IP else False,
        }
        
        # Extract payload if available
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            features["payload_size"] = len(payload)
            features["entropy"] = shannon_entropy(payload)
            features["has_binary"] = any(b > 127 for b in payload[:512])
        else:
            features["payload_size"] = 0
            features["entropy"] = 0.0
            features["has_binary"] = False
        
        # TCP flags if TCP layer exists
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features["tcp_flags"] = {
                "syn": bool(tcp.flags & 0x02),
                "ack": bool(tcp.flags & 0x10),
                "fin": bool(tcp.flags & 0x01),
                "rst": bool(tcp.flags & 0x04),
                "psh": bool(tcp.flags & 0x08),
            }
            features["src_port"] = tcp.sport
            features["dst_port"] = tcp.dport
        
        # IP layer
        if packet.haslayer(IP):
            ip = packet[IP]
            features["src_ip"] = ip.src
            features["dst_ip"] = ip.dst
            features["ttl"] = ip.ttl
        
        return features


class CaptureAdapter:
    """Unified capture adapter supporting both Phase 1 (HTTP) and Phase 2 (PCAP)"""
    
    def __init__(self):
        self.pcap_engine = None
        if settings.enable_phase2_pcap:
            if not SCAPY_AVAILABLE:
                print("[WARNING] Phase 2 PCAP enabled but Scapy not installed. Falling back to HTTP-level features.")
                print("[WARNING] Install with: pip install scapy")
            else:
                print("[PCAP] Phase 2 enabled - initializing packet capture engine")
                self.pcap_engine = PCAPEngine()
                self.pcap_engine.start_capture()
                print(f"[PCAP] Capturing on interface: {settings.pcap_interface}")
                print(f"[PCAP] BPF filter: {settings.pcap_filter}")
    
    def extract_request_features(self, method: str, path: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        """Extract features from HTTP request (Phase 1) or enhance with PCAP data (Phase 2)"""
        
        # Phase 1: HTTP-level features
        entropy = shannon_entropy(body)
        features = {
            "phase": "http_features" if not settings.enable_phase2_pcap else "pcap_enhanced",
            "method": method,
            "path": path,
            "header_count": len(headers),
            "body_size": len(body),
            "entropy": entropy,
            "has_binary_body": any(b > 127 for b in body[:512]),
        }
        
        # Phase 2: Add PCAP-level features if enabled
        if self.pcap_engine and self.pcap_engine.enabled:
            # Get recent packets matching this connection
            recent_packets = self.pcap_engine.packets[-10:]  # Last 10 packets
            if recent_packets:
                features["pcap_packet_count"] = len(recent_packets)
                features["pcap_total_bytes"] = sum(len(pkt) for pkt in recent_packets)
                
                # Extract features from most recent packet
                if recent_packets:
                    pcap_features = self.pcap_engine.extract_features_from_packet(recent_packets[-1])
                    features["pcap_features"] = pcap_features
        
        return features
    
    def extract_response_features(self, status_code: int, headers: dict[str, str], body: bytes) -> dict[str, Any]:
        """Extract features from HTTP response"""
        entropy = shannon_entropy(body)
        features = {
            "status_code": status_code,
            "header_count": len(headers),
            "body_size": len(body),
            "entropy": entropy,
        }
        
        # Phase 2: Add PCAP context if available
        if self.pcap_engine and self.pcap_engine.enabled:
            features["pcap_enabled"] = True
            features["pcap_packets_captured"] = len(self.pcap_engine.packets)
        
        return features
    
    def shutdown(self):
        """Clean shutdown of capture engine"""
        if self.pcap_engine:
            print("[PCAP] Stopping packet capture...")
            self.pcap_engine.stop_capture()
