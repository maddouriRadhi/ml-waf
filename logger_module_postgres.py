import csv
import os
import logging
from datetime import datetime
import threading
from database_config import db_manager

class WAFLogger:
    def __init__(self, log_file='logs/waf_logs.csv'):
        self.log_file = log_file
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        
        # Create logs directory
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Initialize CSV log file
        self._init_csv()
        
        # Initialize PostgreSQL database
        self._init_database()
        
        self.logger.info("WAF Logger initialized with PostgreSQL backend")

    def _init_csv(self):
        """Initialize CSV log file with headers"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'ip', 'method', 'url', 'host', 
                    'ml_score', 'decision', 'reason', 'user_agent'
                ])

    def _init_database(self):
        """Initialize PostgreSQL database tables"""
        try:
            # Create requests table
            db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS requests (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    ip VARCHAR(45) NOT NULL,
                    method VARCHAR(10),
                    url TEXT,
                    host VARCHAR(255),
                    ml_score REAL,
                    decision TEXT,
                    reason TEXT,
                    user_agent TEXT,
                    request_data TEXT
                )
            """, fetch=False)
            
            # Create alerts table
            db_manager.execute_query("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    ip VARCHAR(45) NOT NULL,
                    alert_type TEXT,
                    severity TEXT,
                    message TEXT
                )
            """, fetch=False)
            
            # Create indexes for better performance
            db_manager.execute_query("CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)", fetch=False)
            db_manager.execute_query("CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)", fetch=False)
            db_manager.execute_query("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)", fetch=False)
            db_manager.execute_query("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)", fetch=False)
            
            self.logger.info("PostgreSQL database tables initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing database: {str(e)}")

    def log_request(self, request_info, ml_score, decision):
        """Log a request to both CSV and PostgreSQL database"""
        with self.lock:
            timestamp = request_info.get('timestamp', datetime.now().isoformat())
            ip = request_info.get('ip', 'unknown')
            method = request_info.get('method', 'GET')
            url = request_info.get('url', request_info.get('path', '/'))  # Handle both 'url' and 'path'
            host = request_info.get('host', '')
            user_agent = request_info.get('user_agent', request_info.get('headers', {}).get('User-Agent', ''))  # Handle both formats
            
            # Determine reason
            reason = decision.split(' - ')[1] if ' - ' in decision else decision
            # Normalize decision column to blocked / allowed (lowercase as requested)
            db_decision = 'blocked' if decision.lower().startswith('blocked') else 'allowed'
            
            # Log to CSV
            try:
                with open(self.log_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        timestamp, ip, method, url, host,
                        f"{ml_score:.4f}", decision, reason, user_agent
                    ])
            except Exception as e:
                self.logger.error(f"Error writing to CSV: {str(e)}")
            
            # Log to PostgreSQL database
            try:
                db_manager.execute_query("""
                    INSERT INTO requests 
                    (timestamp, ip, method, url, host, ml_score, decision, reason, user_agent, request_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    timestamp, ip, method, url, host,
                    ml_score, db_decision, reason, user_agent,
                    str(request_info)[:500]  # Convert request_info to string
                ), fetch=False)
            except Exception as e:
                self.logger.error(f"Error writing to database: {str(e)}")

    def create_alert(self, ip, alert_type, severity, message):
        """Create an alert entry"""
        try:
            db_manager.execute_query("""
                INSERT INTO alerts (timestamp, ip, alert_type, severity, message)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                datetime.now().isoformat(),
                ip,
                alert_type,
                severity,
                message
            ), fetch=False)
        except Exception as e:
            self.logger.error(f"Error creating alert: {str(e)}")

    def get_recent_logs(self, limit=100):
        """Get recent log entries"""
        try:
            logs = db_manager.execute_query("""
                SELECT timestamp, ip, method, url, ml_score, decision, reason
                FROM requests
                ORDER BY id DESC
                LIMIT %s
            """, (limit,))
            
            return logs
        except Exception as e:
            self.logger.error(f"Error retrieving logs: {str(e)}")
            return []

    def get_alerts(self, limit=50):
        """Get recent alerts"""
        try:
            alerts = db_manager.execute_query("""
                SELECT timestamp, ip, alert_type, severity, message
                FROM alerts
                ORDER BY id DESC
                LIMIT %s
            """, (limit,))
            
            return alerts
        except Exception as e:
            self.logger.error(f"Error retrieving alerts: {str(e)}")
            return []

    def get_statistics(self, days=7):
        """Get statistics for the last N days"""
        try:
            # Default stats for empty database
            stats = {
                'total_requests': 0,
                'blocked_requests': 0,
                'high_risk_requests': 0,
                'block_rate': 0,
                'top_blocked_ips': []
            }
            
            # Total requests
            result = db_manager.execute_query("""
                SELECT COUNT(*) as total_requests
                FROM requests
                WHERE timestamp >= NOW() - INTERVAL '%s days'
            """, (days,))
            
            if result:
                stats['total_requests'] = result[0]['total_requests']
            
            # Blocked requests
            result = db_manager.execute_query("""
                SELECT COUNT(*) as blocked_requests
                FROM requests
                WHERE decision = 'blocked'
                AND timestamp >= NOW() - INTERVAL '%s days'
            """, (days,))
            
            if result:
                stats['blocked_requests'] = result[0]['blocked_requests']
            
            # Calculate block rate
            if stats['total_requests'] > 0:
                stats['block_rate'] = (stats['blocked_requests'] / stats['total_requests'] * 100)
            
            return stats
        except Exception as e:
            self.logger.error(f"Error getting statistics: {str(e)}")
            return {
                'total_requests': 0,
                'blocked_requests': 0,
                'high_risk_requests': 0,
                'block_rate': 0,
                'top_blocked_ips': []
            }

    def search_logs(self, query, field='url', limit=100):
        """Search logs by query"""
        try:
            # Sanitize field name to prevent SQL injection
            valid_fields = ['url', 'ip', 'method', 'decision', 'reason']
            if field not in valid_fields:
                field = 'url'
            
            results = db_manager.execute_query("""
                SELECT timestamp, ip, method, url, ml_score, decision, reason
                FROM requests
                WHERE {field} ILIKE %s
                ORDER BY timestamp DESC
                LIMIT %s
            """.format(field=field), (f'%{query}%', limit))
            
            return results
        except Exception as e:
            self.logger.error(f"Error searching logs: {str(e)}")
            return []
