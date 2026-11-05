

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
    
    MAX_HEADER_BYTES = 65536
    MAX_BODY_BYTES = 5 * 1024 * 1024

    def _read_http_request(self, client_socket):
        """Read one complete HTTP request: headers, then exactly Content-Length body bytes.
        Returns (request_line, headers, body_bytes), None, or an error keyword."""
        client_socket.settimeout(15)
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > self.MAX_HEADER_BYTES:
                return 'TOO_LARGE'
        if not data:
            return None
        if b'\r\n\r\n' not in data:
            return 'BAD'
        head, _, body = data.partition(b'\r\n\r\n')
        lines = head.decode('utf-8', errors='replace').split('\r\n')
        request_line = lines[0].strip()
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        if 'chunked' in headers.get('transfer-encoding', '').lower():
            return 'CHUNKED'
        try:
            length = int(headers.get('content-length', '0') or 0)
        except ValueError:
            return 'BAD'
        if length < 0 or length > self.MAX_BODY_BYTES:
            return 'TOO_LARGE'
        while len(body) < length:
            chunk = client_socket.recv(min(65536, length - len(body)))
            if not chunk:
                break
            body += chunk
        return request_line, headers, body[:length]

    def handle_client(self, client_socket, client_address):
        """Handle incoming client requests"""
        try:
            result = self._read_http_request(client_socket)
            if result is None:
                return
            if isinstance(result, str):
                errors = {
                    'TOO_LARGE': (413, 'Payload Too Large'),
                    'CHUNKED': (411, 'Length Required'),
                    'BAD': (400, 'Bad Request'),
                }
                code, message = errors.get(result, (400, 'Bad Request'))
                self.send_error_response(client_socket, code, message)
                return

            request_line, headers, body_bytes = result
            parts = request_line.split(' ')
            if len(parts) < 3:
                self.send_bad_request(client_socket)
                return

            method, path, version = parts[0], parts[1], parts[2]
            body = body_bytes.decode('utf-8', errors='replace')

            src_ip = client_address[0]
            # Log the request
            self.logger.info(f"Request from {src_ip}: {method} {path}")

            # Apply WAF filters and determine if should block
            should_block = self.should_block_request(method, path, body, headers, src_ip)

            # If request should be blocked, apply blocking
            if should_block:
                self.block_request(client_socket, method, path, client_address)
                return

            # Forward to backend (raw bytes, exactly as received)
            self.forward_request(client_socket, method, path, headers, body_bytes)

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
    
    # Headers that must not be copied blindly from client to backend
    _SKIP_REQUEST_HEADERS = {
        'host', 'connection', 'keep-alive', 'content-length', 'accept-encoding',
        'transfer-encoding', 'te', 'trailers', 'upgrade',
        'proxy-authorization', 'proxy-authenticate',
    }
    # Headers that must not be copied blindly from backend to client
    _SKIP_RESPONSE_HEADERS = {
        'connection', 'keep-alive', 'transfer-encoding', 'content-length',
        'content-encoding', 'set-cookie',
    }

    def forward_request(self, client_socket, method, path, headers, body):
        """Forward request to backend server and relay the response unchanged"""
        try:
            if isinstance(body, str):
                body = body.encode('utf-8')

            url = f"http://{self.backend_host}:{self.backend_port}{path}"
            # Keep the client's Host so the backend builds links/redirects that point
            # back to the WAF, instead of to the unprotected backend port.
            client_host = headers.get('host') or '127.0.0.1:8085'

            backend_headers = {
                key: value for key, value in headers.items()
                if key.lower() not in self._SKIP_REQUEST_HEADERS
            }
            backend_headers['Host'] = client_host
            backend_headers['Accept-Encoding'] = 'identity'

            response = requests.request(
                method, url,
                headers=backend_headers,
                data=body if body else None,
                allow_redirects=False,   # the browser must follow redirects, with its cookies
                timeout=30,
            )

            content = response.content
            out = [f"HTTP/1.1 {response.status_code} {response.reason}\r\n"]
            for key, value in response.headers.items():
                lower = key.lower()
                if lower in self._SKIP_RESPONSE_HEADERS:
                    continue
                if lower == 'location':
                    value = value.replace(
                        f"http://{self.backend_host}:{self.backend_port}", f"http://{client_host}")
                out.append(f"{key}: {value}\r\n")

            # One Set-Cookie line per cookie (a dict would merge them with commas)
            try:
                cookies = response.raw.headers.getlist('Set-Cookie')
            except Exception:
                cookies = []
            for cookie in cookies:
                out.append(f"Set-Cookie: {cookie}\r\n")

            if method.upper() == 'HEAD':
                out.append(f"Content-Length: {response.headers.get('content-length', '0')}\r\n")
            else:
                out.append(f"Content-Length: {len(content)}\r\n")
            out.append("Connection: close\r\n\r\n")

            client_socket.sendall(''.join(out).encode('utf-8', errors='replace'))
            if method.upper() != 'HEAD' and content:
                client_socket.sendall(content)

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
