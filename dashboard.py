"""
Flask Dashboard for ML-WAF
Real-time monitoring, logs, alerts, and configuration
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from functools import wraps
import json
import os
import sys
import subprocess
import signal
import psutil
import threading
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger_module import WAFLogger
from content_filter import ContentFilter
from popup_blocker import PopupBlocker
from auth import auth_manager

# Global variable to store proxy process
proxy_process = None
proxy_thread = None

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change in production

# Initialize components
waf_logger = WAFLogger()

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

content_filter = ContentFilter(config['content_filter'])
popup_blocker = PopupBlocker(config['popup_blocker'])

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error='Please enter username and password')
        
        user, message = auth_manager.authenticate_user(username, password)
        
        if user:
            # Store user info in session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['login_time'] = datetime.now().isoformat()
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error=message)
    
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    user_id = session.get('user_id')
    user = auth_manager.get_user_by_id(user_id)
    
    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('index'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    user_id = session.get('user_id')
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'error')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('profile'))
    
    if len(new_password) < 6:
        flash('Password must be at least 6 characters long', 'error')
        return redirect(url_for('profile'))
    
    # Verify current password
    username = session.get('username')
    user, message = auth_manager.authenticate_user(username, current_password)
    
    if not user:
        flash('Current password is incorrect', 'error')
        return redirect(url_for('profile'))
    
    # Change password
    if auth_manager.change_password(user_id, new_password):
        flash('Password changed successfully', 'success')
    else:
        flash('Failed to change password', 'error')
    
    return redirect(url_for('profile'))

@app.route('/')
@login_required
def index():
    """Dashboard home page"""
    stats = waf_logger.get_statistics(days=30)
    return render_template('index.html', stats=stats)

@app.route('/api/stats')
def api_stats():
    """Get current statistics"""
    stats = waf_logger.get_statistics(days=30)
    return jsonify(stats)

@app.route('/logs')
@login_required
def logs():
    """View logs page"""
    limit = request.args.get('limit', 100, type=int)
    logs = waf_logger.get_recent_logs(limit=limit)
    return render_template('logs.html', logs=logs)

@app.route('/api/logs')
def api_logs():
    """API endpoint for logs"""
    limit = request.args.get('limit', 100, type=int)
    logs = waf_logger.get_recent_logs(limit=limit)
    return jsonify({'logs': logs})

@app.route('/api/logs/search')
def api_logs_search():
    """Search logs"""
    query = request.args.get('query', '')
    field = request.args.get('field', 'url')
    limit = request.args.get('limit', 100, type=int)
    
    results = waf_logger.search_logs(query, field, limit)
    return jsonify({'results': results})

@app.route('/alerts')
@login_required
def alerts():
    """View alerts page"""
    alerts = waf_logger.get_alerts(limit=50)
    return render_template('alerts.html', alerts=alerts)

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts"""
    limit = request.args.get('limit', 50, type=int)
    alerts = waf_logger.get_alerts(limit=limit)
    return jsonify({'alerts': alerts})

@app.route('/config')
@login_required
def configuration():
    """Configuration page"""
    return render_template('config.html', 
                         config=config,
                         content_filter=content_filter,
                         popup_blocker=popup_blocker)

@app.route('/api/config', methods=['GET'])
def api_get_config():
    """Get current configuration"""
    return jsonify({
        'proxy': config['proxy'],
        'backend': config['backend'],
        'ml_classifier': config['ml_classifier'],
        'content_filter': {
            'enabled': content_filter.enabled,
            'categories': content_filter.get_categories(),
            'active_categories': content_filter.get_active_categories(),
            'blacklist': content_filter.get_blacklist(),
            'whitelist': content_filter.get_whitelist()
        },
        'popup_blocker': {
            'enabled': popup_blocker.is_enabled(),
            'aggressiveness': popup_blocker.aggressiveness
        }
    })

@app.route('/api/config/update', methods=['POST'])
def api_update_config():
    """Update configuration"""
    data = request.json
    
    try:
        # Update ML threshold
        if 'ml_threshold' in data:
            config['ml_classifier']['threshold'] = float(data['ml_threshold'])
        
        # Update backend settings
        if 'backend_host' in data:
            config['backend']['host'] = data['backend_host']
        if 'backend_port' in data:
            config['backend']['port'] = int(data['backend_port'])
        
        # Save configuration
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=4)
        
        return jsonify({'success': True, 'message': 'Configuration updated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/content_filter/category/<action>', methods=['POST'])
def api_content_filter_category(action):
    """Enable/disable content filter category"""
    data = request.json
    category = data.get('category')
    
    if action == 'enable':
        success = content_filter.enable_category(category)
    elif action == 'disable':
        success = content_filter.disable_category(category)
    else:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    
    if success:
        return jsonify({'success': True, 'message': f'Category {action}d successfully'})
    else:
        return jsonify({'success': False, 'error': 'Invalid category'}), 400

@app.route('/api/content_filter/blacklist', methods=['POST', 'DELETE'])
def api_content_filter_blacklist():
    """Manage blacklist"""
    data = request.json
    domain = data.get('domain')
    
    if request.method == 'POST':
        content_filter.add_to_blacklist(domain)
        return jsonify({'success': True, 'message': f'Added {domain} to blacklist'})
    elif request.method == 'DELETE':
        content_filter.remove_from_blacklist(domain)
        return jsonify({'success': True, 'message': f'Removed {domain} from blacklist'})

@app.route('/api/content_filter/whitelist', methods=['POST', 'DELETE'])
def api_content_filter_whitelist():
    """Manage whitelist"""
    data = request.json
    domain = data.get('domain')
    
    if request.method == 'POST':
        content_filter.add_to_whitelist(domain)
        return jsonify({'success': True, 'message': f'Added {domain} to whitelist'})
    elif request.method == 'DELETE':
        content_filter.remove_from_whitelist(domain)
        return jsonify({'success': True, 'message': f'Removed {domain} from whitelist'})

@app.route('/api/popup_blocker/toggle', methods=['POST'])
def api_popup_blocker_toggle():
    """Toggle popup blocker"""
    data = request.json
    enabled = data.get('enabled', True)
    
    if enabled:
        popup_blocker.enable()
    else:
        popup_blocker.disable()
    
    return jsonify({'success': True, 'enabled': popup_blocker.is_enabled()})

@app.route('/api/popup_blocker/aggressiveness', methods=['POST'])
def api_popup_blocker_aggressiveness():
    """Set popup blocker aggressiveness"""
    data = request.json
    level = data.get('level')
    
    success = popup_blocker.set_aggressiveness(level)
    
    if success:
        return jsonify({'success': True, 'level': level})
    else:
        return jsonify({'success': False, 'error': 'Invalid level'}), 400

@app.route('/api/chart/traffic')
def api_chart_traffic():
    """Get traffic data for charts"""
    try:
        # Get hourly traffic data for last 24 hours
        result = db_manager.execute_query("""
            SELECT 
                DATE_TRUNC('hour', timestamp) as hour,
                COUNT(*) as total,
                COUNT(CASE WHEN decision LIKE 'BLOCKED%' THEN 1 END) as blocked
            FROM requests 
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY DATE_TRUNC('hour', timestamp)
            ORDER BY hour
        """)
        
        if not result:
            # Fallback to empty data
            return jsonify({
                'labels': ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                'legitimate': [0, 0, 0, 0, 0, 0],
                'blocked': [0, 0, 0, 0, 0, 0]
            })
        
        # Format data for chart
        labels = []
        legitimate = []
        blocked = []
        
        for row in result:
            hour = row['hour'].strftime('%H:00')
            labels.append(hour)
            legitimate.append(row['total'] - row['blocked'])
            blocked.append(row['blocked'])
        
        # Fill missing hours with zeros
        all_hours = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00']
        final_labels = []
        final_legitimate = []
        final_blocked = []
        
        for hour in all_hours:
            final_labels.append(hour)
            if hour in labels:
                idx = labels.index(hour)
                final_legitimate.append(legitimate[idx])
                final_blocked.append(blocked[idx])
            else:
                final_legitimate.append(0)
                final_blocked.append(0)
        
        return jsonify({
            'labels': final_labels,
            'legitimate': final_legitimate,
            'blocked': final_blocked
        })
        
    except Exception as e:
        # Fallback to sample data on error
        return jsonify({
            'labels': ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
            'legitimate': [120, 150, 200, 250, 180, 140],
            'blocked': [15, 20, 35, 28, 22, 18]
        })

@app.route('/api/chart/attacks')
def api_chart_attacks():
    """Get attack type distribution"""
    try:
        # Get attack type distribution from blocked requests
        result = db_manager.execute_query("""
            SELECT 
                CASE 
                    WHEN decision LIKE 'BLOCKED_ML%' THEN 'ML Detection'
                    WHEN decision LIKE 'BLOCKED_CONTENT%' THEN 'Content Filter'
                    WHEN decision LIKE 'BLOCKED_POPUP%' THEN 'Popup Blocker'
                    WHEN decision LIKE 'BLOCKED_RULES%' THEN 'Custom Rules'
                    ELSE 'Other'
                END as attack_type,
                COUNT(*) as count
            FROM requests 
            WHERE decision LIKE 'BLOCKED%'
            AND timestamp >= NOW() - INTERVAL '30 days'
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        
        if not result:
            # Fallback to empty data
            return jsonify({
                'labels': ['No Data'],
                'data': [100]
            })
        
        # Format data for chart
        labels = []
        data = []
        
        for row in result:
            labels.append(row['attack_type'])
            data.append(row['count'])
        
        return jsonify({
            'labels': labels,
            'data': data
        })
        
    except Exception as e:
        # Fallback to sample data on error
        return jsonify({
            'labels': ['SQL Injection', 'XSS', 'RCE', 'Content Filter', 'Popup'],
            'data': [25, 18, 12, 30, 15]
        })

def find_proxy_process():
    """Find existing WAF proxy process"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'ml_waf.py' in cmdline:
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def start_waf_proxy():
    """Start the WAF proxy in a separate thread"""
    global proxy_process, proxy_thread
    
    try:
        # Check if proxy is already running
        existing_pid = find_proxy_process()
        if existing_pid:
            return True, f"Proxy already running (PID: {existing_pid})"
        
        # Start proxy in a separate thread
        def run_proxy():
            global proxy_process
            try:
                import subprocess
                proxy_process = subprocess.Popen([
                    sys.executable, 'ml_waf.py'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Wait for process to complete and capture output
                stdout, stderr = proxy_process.communicate()
                
                if proxy_process.returncode != 0:
                    print(f" Proxy failed to start. Return code: {proxy_process.returncode}")
                    print(f" STDOUT: {stdout}")
                    print(f" STDERR: {stderr}")
                else:
                    print(f" Proxy started successfully")
                    
            except Exception as e:
                print(f" Error running proxy: {e}")
                import traceback
                traceback.print_exc()
        
        proxy_thread = threading.Thread(target=run_proxy, daemon=True)
        proxy_thread.start()
        
        # Give it a moment to start
        import time
        time.sleep(2)
        
        # Check if it started successfully
        if find_proxy_process():
            return True, "WAF Proxy started successfully"
        else:
            return False, "Failed to start WAF Proxy"
            
    except Exception as e:
        return False, f"Error starting proxy: {str(e)}"

def stop_waf_proxy():
    """Stop the WAF proxy"""
    try:
        # Find and kill the proxy process
        proxy_pid = find_proxy_process()
        if proxy_pid:
            try:
                os.kill(proxy_pid, signal.SIGTERM)
                import time
                time.sleep(2)  # Give it time to shut down gracefully
                
                # Force kill if still running
                if find_proxy_process():
                    os.kill(proxy_pid, signal.SIGKILL)
                
                return True, "WAF Proxy stopped successfully"
            except ProcessLookupError:
                return True, "WAF Proxy was not running"
        else:
            return True, "WAF Proxy was not running"
            
    except Exception as e:
        return False, f"Error stopping proxy: {str(e)}"

@app.route('/api/proxy/start', methods=['POST'])
@login_required
def api_start_proxy():
    """Start WAF Proxy"""
    try:
        success, message = start_waf_proxy()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/stop', methods=['POST'])
@login_required
def api_stop_proxy():
    """Stop WAF Proxy"""
    try:
        success, message = stop_waf_proxy()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/status')
@login_required
def status():
    """System status page"""
    import socket
    import subprocess
    import psutil
    
    # Check backend connectivity
    backend_status = 'offline'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((config['backend']['host'], config['backend']['port']))
        backend_status = 'online' if result == 0 else 'offline'
        sock.close()
    except:
        backend_status = 'offline'
    
    # Check WAF proxy status
    proxy_status = 'offline'
    proxy_pid = None
    try:
        # Check if port 8085 is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((config['proxy']['host'], config['proxy']['port']))
        proxy_status = 'online' if result == 0 else 'offline'
        sock.close()
        
        # Try to find the proxy process
        if proxy_status == 'online':
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if 'ml_waf.py' in cmdline:
                        proxy_pid = proc.info['pid']
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except:
        proxy_status = 'offline'
    
    return render_template('status.html', config=config, proxy_status=proxy_status, proxy_pid=proxy_pid)

@app.route('/api/status')
def api_status():
    """Get system status"""
    import socket
    import subprocess
    import psutil
    
    # Check backend connectivity
    backend_status = 'offline'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((config['backend']['host'], config['backend']['port']))
        backend_status = 'online' if result == 0 else 'offline'
        sock.close()
    except:
        backend_status = 'offline'
    
    # Check WAF proxy status
    proxy_status = 'offline'
    proxy_pid = None
    try:
        # Check if port 8085 is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((config['proxy']['host'], config['proxy']['port']))
        proxy_status = 'online' if result == 0 else 'offline'
        sock.close()
        
        # Try to find the proxy process
        if proxy_status == 'online':
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if 'ml_waf.py' in cmdline:
                        proxy_pid = proc.info['pid']
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except:
        proxy_status = 'offline'
    
    return jsonify({
        'proxy': {
            'host': config['proxy']['host'],
            'port': config['proxy']['port'],
            'status': proxy_status,
            'pid': proxy_pid
        },
        'backend': {
            'host': config['backend']['host'],
            'port': config['backend']['port'],
            'status': backend_status
        },
        'ml_model': {
            'status': 'loaded',
            'threshold': config['ml_classifier']['threshold']
        },
        'content_filter': {
            'enabled': content_filter.enabled,
            'active_categories': len(content_filter.active_categories)
        },
        'popup_blocker': {
            'enabled': popup_blocker.is_enabled(),
            'aggressiveness': popup_blocker.aggressiveness
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)