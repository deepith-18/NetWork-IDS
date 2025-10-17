# FILE: core/attack_detector.py
import time
from collections import defaultdict

class AttackDetector:
    def __init__(self):
        # Port scan detection
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'time': time.time()})
        
        # SYN flood detection
        self.syn_tracker = defaultdict(int)
        self.syn_reset_time = time.time()
        
        # ICMP flood detection
        self.icmp_tracker = defaultdict(int)
        self.icmp_reset_time = time.time()
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 20  # unique ports
        self.PORT_SCAN_WINDOW = 60  # seconds
        self.SYN_FLOOD_THRESHOLD = 100  # packets per second
        self.ICMP_FLOOD_THRESHOLD = 50  # packets per second
        
    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scanning activity"""
        current_time = time.time()
        tracker = self.port_scan_tracker[src_ip]
        
        if current_time - tracker['time'] > self.PORT_SCAN_WINDOW:
            tracker['ports'] = set()
            tracker['time'] = current_time
        
        tracker['ports'].add(dst_port)
        
        if len(tracker['ports']) > self.PORT_SCAN_THRESHOLD:
            return {
                'type': 'Port Scan',
                'severity': 'High',
                'src_ip': src_ip,
                'description': f'Port scan detected: {len(tracker["ports"])} ports scanned'
            }
        return None
    
    def detect_syn_flood(self, packet_info):
        """Detect SYN flood attack"""
        if packet_info.get('protocol') != 'TCP' or packet_info.get('flags') != 'S':
            return None
        
        current_time = time.time()
        
        if current_time - self.syn_reset_time > 1:
            self.syn_tracker.clear()
            self.syn_reset_time = current_time
        
        src_ip = packet_info['src_ip']
        self.syn_tracker[src_ip] += 1
        
        if self.syn_tracker[src_ip] > self.SYN_FLOOD_THRESHOLD:
            return {
                'type': 'SYN Flood',
                'severity': 'Critical',
                'src_ip': src_ip,
                'description': f'SYN flood detected: {self.syn_tracker[src_ip]} packets/sec'
            }
        return None
    
    def detect_icmp_flood(self, packet_info):
        """Detect ICMP flood attack"""
        if packet_info.get('protocol') != 'ICMP':
            return None
        
        current_time = time.time()
        
        if current_time - self.icmp_reset_time > 1:
            self.icmp_tracker.clear()
            self.icmp_reset_time = current_time
        
        src_ip = packet_info['src_ip']
        self.icmp_tracker[src_ip] += 1
        
        if self.icmp_tracker[src_ip] > self.ICMP_FLOOD_THRESHOLD:
            return {
                'type': 'ICMP Flood',
                'severity': 'High',
                'src_ip': src_ip,
                'description': f'ICMP flood detected: {self.icmp_tracker[src_ip]} packets/sec'
            }
        return None
    
    def analyze_packet(self, packet_info):
        """Main analysis method - check all attack types"""
        alerts = []
        
        if 'dst_port' in packet_info:
            alert = self.detect_port_scan(packet_info['src_ip'], packet_info['dst_port'])
            if alert: alerts.append(alert)
        
        alert = self.detect_syn_flood(packet_info)
        if alert: alerts.append(alert)
        
        alert = self.detect_icmp_flood(packet_info)
        if alert: alerts.append(alert)
        
        return alerts