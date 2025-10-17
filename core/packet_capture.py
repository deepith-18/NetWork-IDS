# FILE: core/packet_capture.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

class PacketCapture:
    def __init__(self, callback):
        self.callback = callback
        self.is_running = False
        self.capture_thread = None
        
    def packet_handler(self, packet):
        """Process each captured packet"""
        if packet.haslayer(IP):
            packet_info = {
                'timestamp': packet.time,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': self.get_protocol(packet),
                'length': len(packet)
            }
            
            # Add port information if available
            if packet.haslayer(TCP):
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
            elif packet.haslayer(UDP):
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
            
            # Send to callback for processing
            self.callback(packet_info, packet)
    
    def get_protocol(self, packet):
        """Identify protocol type"""
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        else:
            return 'OTHER'
    
    def start(self, interface=None, packet_filter=None):
        """Start packet capture"""
        if self.is_running:
            print("Capture already running")
            return
        
        self.is_running = True
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, packet_filter)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        print(f"Started packet capture on {interface or 'default interface'}")
    
    def _capture_packets(self, interface, packet_filter):
        """Internal capture method"""
        try:
            sniff(
                iface=interface,
                prn=self.packet_handler,
                filter=packet_filter,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"Capture error: {e}")
            self.is_running = False
    
    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        print("Stopped packet capture")