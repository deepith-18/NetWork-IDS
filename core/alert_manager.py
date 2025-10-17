# FILE: core/alert_manager.py
import json
from datetime import datetime
import os

class AlertManager:
    def __init__(self):
        self.alerts = []
        self.alert_log_file = 'logs/alerts.log'
        os.makedirs('logs', exist_ok=True)
        
    def create_alert(self, alert_type, severity, src_ip, description):
        """Create a new alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert_type,
            'severity': severity,
            'src_ip': src_ip,
            'description': description,
            'status': 'new'
        }
        
        self.alerts.append(alert)
        self.log_alert(alert)
        
        return alert
    
    def log_alert(self, alert):
        """Log alert to file"""
        try:
            with open(self.alert_log_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            print(f"Error logging alert: {e}")
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts"""
        return sorted(self.alerts, key=lambda x: x['id'], reverse=True)[:limit]
    
    def get_alert_stats(self):
        """Get alert statistics"""
        stats = {
            'total': len(self.alerts),
            'critical': sum(1 for a in self.alerts if a['severity'] == 'Critical'),
            'high': sum(1 for a in self.alerts if a['severity'] == 'High'),
            'medium': sum(1 for a in self.alerts if a['severity'] == 'Medium'),
            'low': sum(1 for a in self.alerts if a['severity'] == 'Low')
        }
        return stats