

import socket
import threading
import json
import logging
import sys
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import requests

class MLWAFProxy:
    """ML-based WAF Proxy Server"""
    
    def __init__(self, config_file='config.json'):
        self.config = self.load_config(config_file)
        self.host = self.config['proxy']['host']
        self.port = self.config['proxy']['port']
        self.backend_host = self.config['backend']['host']
        self.backend_port = self.config['backend']['port']
        
        # Initialize components
        self.predictor = None
        self.content_filter = None
        self.popup_blocker = None
        self.waf_logger = None
        
        # Try to initialize WAF components (optional)
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from initial_waf_predictor import InitialWAFPredictor
            from content_filter import ContentFilter
            from popup_blocker import PopupBlocker
            from logger_module import WAFLogger
            
            self.predictor = InitialWAFPredictor()
            self.content_filter = ContentFilter(self.config['content_filter'])
            self.popup_blocker = PopupBlocker(self.config['popup_blocker'])
            self.waf_logger = WAFLogger()
            print("✅ WAF components loaded successfully with trained model")
        except ImportError as e:
            print(f"Warning: WAF components not available: {e}")
            print("Running in basic proxy mode without ML filtering")
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, self.config['logging']['level']),
            format=self.config['logging']['format'],
            handlers=[
                logging.FileHandler(self.config['logging']['file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        self.running = False
        self.server_socket = None
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    
    def start(self):
        """Start the proxy server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            self.logger.info(f"ML-WAF Proxy started on {self.host}:{self.port}")
            print(f"ML-WAF Proxy running on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error starting server: {e}")
            print(f"Failed to start server: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("ML-WAF Proxy stopped")
    
    def handle_client(self, client_socket, client_address):
        """Handle incoming client requests"""
        try:
            # Receive request
            request_data = client_socket.recv(4096).decode('utf-8')
            if not request_data:
                client_socket.close()
                return
            
            # Parse HTTP request
            request_lines = request_data.split('\n')
            if len(request_lines) == 0:
                client_socket.close()
                return
            
            request_line = request_lines[0].strip()
            parts = request_line.split(' ')
            
            if len(parts) < 3:
                self.send_bad_request(client_socket)
                return
            
            method, path, version = parts[0], parts[1], parts[2]
            
            # Extract headers and body
            headers = {}
            body = ''
            body_started = False
            
            for line in request_lines[1:]:
                line = line.strip()
                if line == '':
                    body_started = True
                    continue
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                else:
                    body += line + '\n'
            
            src_ip = client_address[0]
            # Log the request
            self.logger.info(f"Request from {src_ip}: {method} {path}")
            
            # Apply WAF filters and determine if should block
            should_block = self.should_block_request(method, path, body, headers, src_ip)
            
            # If request should be blocked, apply blocking
            if should_block:
                self.block_request(client_socket, method, path, client_address)
                return
            
            # Forward to backend
            self.forward_request(client_socket, method, path, headers, body)
            
        except Exception as e:
            self.logger.error(f"Error handling client {client_address}: {e}")
            self.send_error_response(client_socket, 500, "Internal Server Error")
        finally:
            client_socket.close()
    
    def should_block_request(self, method, path, body, headers, src_ip):
        """Check if request should be blocked using trained WAF model"""
        try:
            # Create request info for logging
            request_info = {
                'timestamp': datetime.now().isoformat(),
                'method': method,
                'url': path,  
                'host': headers.get('host', ''),
                'user_agent': headers.get('user-agent', ''),
                'ip': src_ip
            }
            
            # Default: allow request
            should_block = False
            probability = 0.0
            decision_reason = 'legitimate'
            
            # Use trained ML model if available
            if self.predictor:
                is_malicious, probability = self.predictor.is_malicious(method, path, body)
                
                if is_malicious:
                    should_block = True
                    decision_reason = 'blocked_ml'
                    self.logger.warning(f"ML Model BLOCKED: {method} {path} (prob: {probability:.3f})")
                    
                    # Create alert for high-confidence blocks
                    if self.waf_logger:
                        self.waf_logger.create_alert(
                            src_ip,
                            'ML Detection',
                            'HIGH',
                            f'ML model blocked {method} {path} with probability {probability:.3f}'
                        )
                else:
                    self.logger.info(f"ML Model ALLOWED: {method} {path} (prob: {probability:.3f})")
            
            # Additional content filtering (if available)
            if not should_block and self.content_filter:
                if self.content_filter.should_block_url(path, headers.get('host', '')) or \
                   self.content_filter.should_block_content(body):
                    should_block = True
                    decision_reason = 'blocked_content'
                    probability = 1.0
                    self.logger.warning(f"Content Filter BLOCKED: {method} {path}")
                    
                    if self.waf_logger:
                        self.waf_logger.create_alert(
                            src_ip,
                            'Content Filter',
                            'MEDIUM',
                            f'Content filter blocked {method} {path}'
                        )
            
            # Popup blocking (if available)
            if not should_block and self.popup_blocker:
                if self.popup_blocker.detect_popup(body):
                    should_block = True
                    decision_reason = 'blocked_popup'
                    probability = 1.0
                    self.logger.warning(f"Popup Blocker BLOCKED: {method} {path}")
                    
                    if self.waf_logger:
                        self.waf_logger.create_alert(
                            src_ip,
                            'Popup Blocker',
                            'LOW',
                            f'Popup blocker blocked {method} {path}'
                        )
            
            # Log the final decision
            if self.waf_logger:
                self.waf_logger.log_request(request_info, probability, decision_reason)
            
            return should_block
            
        except Exception as e:
            self.logger.error(f"Error in should_block_request: {e}")
            # Default to allowing request on error
            return False
    
    def block_request(self, client_socket, method, path, client_address):
        """Send blocked response"""
        response = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF</p></body></html>"
        )
        client_socket.send(response.encode('utf-8'))
        self.logger.warning(f"Blocked request sent to {client_address}: {method} {path}")
    
    def forward_request(self, client_socket, method, path, headers, body):
        """Forward request to backend server"""
        try:
            # Construct backend URL
            url = f"http://{self.backend_host}:{self.backend_port}{path}"
            
            # Prepare headers for backend request
            backend_headers = {}
            for key, value in headers.items():
                if key.lower() not in ['host', 'connection']:
                    backend_headers[key] = value
            
            # Make request to backend
            if method.upper() == 'GET':
                response = requests.get(url, headers=backend_headers, timeout=10)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=backend_headers, data=body, timeout=10)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=backend_headers, data=body, timeout=10)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=backend_headers, timeout=10)
            else:
                response = requests.request(method, url, headers=backend_headers, data=body, timeout=10)
            
            # Forward response to client
            response_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
            client_socket.send(response_line.encode('utf-8'))
            
            # Forward headers
            for key, value in response.headers.items():
                if key.lower() not in ['connection', 'transfer-encoding']:
                    header_line = f"{key}: {value}\r\n"
                    client_socket.send(header_line.encode('utf-8'))
            
            client_socket.send(b"\r\n")
            
            # Forward body
            if response.content:
                client_socket.send(response.content)
            
            self.logger.info(f"Forwarded {method} {path} -> {response.status_code}")
            
        except Exception as e:
            self.logger.error(f"Error forwarding request: {e}")
            self.send_error_response(client_socket, 502, "Bad Gateway")
    
    def send_bad_request(self, client_socket):
        """Send 400 Bad Request response"""
        response = (
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html><body><h1>400 Bad Request</h1></body></html>"
        )
        client_socket.send(response.encode('utf-8'))
    
    def send_error_response(self, client_socket, status_code, message):
        """Send error response"""
        response = (
            f"HTTP/1.1 {status_code} {message}\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"<html><body><h1>{status_code} {message}</h1></body></html>"
        )
        client_socket.send(response.encode('utf-8'))

def main():
    """Main function to run the ML-WAF proxy"""
    print("Starting ML-WAF Proxy...")
    
    try:
        proxy = MLWAFProxy()
        proxy.start()
    except KeyboardInterrupt:
        print("\nShutting down ML-WAF Proxy...")
        proxy.stop()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
