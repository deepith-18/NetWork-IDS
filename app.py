# FILE: app.py
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from core.packet_capture import PacketCapture
from core.attack_detector import AttackDetector
from core.alert_manager import AlertManager
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
# Corrected SocketIO initialization (no async_mode specified)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
alert_manager = AlertManager()
attack_detector = AttackDetector()
packet_capture = None

# Statistics
stats = {
    'total_packets': 0,
    'tcp_packets': 0,
    'udp_packets': 0,
    'icmp_packets': 0,
    'other_packets': 0,
    'packets_per_sec': 0,
    'start_time': None
}

recent_packets = []
MAX_RECENT_PACKETS = 100

def packet_callback(packet_info, raw_packet):
    """Callback for processing captured packets"""
    global stats, recent_packets
    
    stats['total_packets'] += 1
    protocol = packet_info.get('protocol', 'OTHER')
    
    if protocol == 'TCP': stats['tcp_packets'] += 1
    elif protocol == 'UDP': stats['udp_packets'] += 1
    elif protocol == 'ICMP': stats['icmp_packets'] += 1
    else: stats['other_packets'] += 1
    
    if stats['start_time']:
        elapsed = time.time() - stats['start_time']
        if elapsed > 0:
            stats['packets_per_sec'] = int(stats['total_packets'] / elapsed)
    
    recent_packets.append(packet_info)
    if len(recent_packets) > MAX_RECENT_PACKETS:
        recent_packets.pop(0)
    
    alerts = attack_detector.analyze_packet(packet_info)
    
    for alert_data in alerts:
        alert = alert_manager.create_alert(
            alert_data['type'],
            alert_data['severity'],
            alert_data['src_ip'],
            alert_data['description']
        )
        socketio.emit('new_alert', alert)
    
    socketio.emit('new_packet', {
        'protocol': protocol,
        'src_ip': packet_info.get('src_ip'),
        'dst_ip': packet_info.get('dst_ip'),
        'stats': stats
    })

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    global packet_capture, stats
    
    if packet_capture and packet_capture.is_running:
        return jsonify({'status': 'error', 'message': 'Already running'})
    
    # Reset stats for a new session
    stats = {k: 0 for k in stats}
    stats['start_time'] = time.time()
    
    data = request.get_json() or {}
    interface = data.get('interface')
    
    packet_capture = PacketCapture(packet_callback)
    packet_capture.start(interface=interface)
    
    return jsonify({'status': 'success', 'message': 'Monitoring started'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    global packet_capture
    if packet_capture and packet_capture.is_running:
        packet_capture.stop()
        return jsonify({'status': 'success', 'message': 'Monitoring stopped'})
    return jsonify({'status': 'error', 'message': 'Not running'})

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'stats': stats,
        'alerts': alert_manager.get_alert_stats()
    })

@app.route('/api/alerts')
def get_alerts():
    limit = request.args.get('limit', 50, type=int)
    return jsonify({'alerts': alert_manager.get_recent_alerts(limit)})

if __name__ == '__main__':
    print("="*50)
    print("  Network Intrusion Detection System")
    print("="*50)
    print("\nStarting Flask-SocketIO server...")
    print("Access dashboard at: http://localhost:5000")
    print("\nNOTE: This script must be run with sudo/administrator privileges.")
    print("="*50)
    socketio.run(app, host='0.0.0.0', port=5000)