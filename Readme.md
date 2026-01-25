# Machine Learning-Based Web Application Firewall (ML-WAF)

A comprehensive, intelligent Web Application Firewall powered by Machine Learning with real-time monitoring dashboard, advanced content filtering, and popup blocking capabilities. This system provides enterprise-grade security features with an intuitive web interface for monitoring and configuration.

## 🚀 Key Features

### 🔒 Security & Protection
- **ML-Based Threat Detection**: Advanced Logistic Regression model for real-time malicious traffic classification
- **Multi-Attack Pattern Recognition**: Detection of SQL Injection, XSS, Remote Code Execution, Path Traversal, and more
- **Bidirectional Traffic Control**: Comprehensive monitoring of both inbound requests and outbound responses
- **Intelligent Rate Limiting**: Prevents abuse and DoS attacks with configurable thresholds
- **IP Whitelisting/Blacklisting**: Granular access control based on IP addresses

### 🌐 Content Filtering
- **Category-Based Blocking**: Block sports, gambling, adult content, social media, streaming sites
- **Advanced URL Pattern Matching**: Flexible keyword and regex-based filtering
- **Deep Content Analysis**: Comprehensive inspection of HTTP response bodies
- **Dynamic Whitelist/Blacklist Management**: Real-time domain-level access control

### 🚫 Popup & Script Blocking
- **JavaScript Pattern Detection**: Advanced identification of popup-generating code
- **CSP Injection**: Content Security Policy enforcement for modern browsers
- **Target Attribute Modification**: Converts `_blank` to `_self` to prevent new windows
- **Configurable Aggressiveness**: Strict, Moderate, or Permissive blocking modes

### 📊 Real-Time Monitoring Dashboard
- **Live Traffic Statistics**: Real-time metrics and attack analytics
- **Interactive Charts**: Traffic trends and attack type distribution visualization
- **Comprehensive Logging**: PostgreSQL database with advanced search capabilities
- **Intelligent Alert System**: Security event notifications with severity levels
- **Web-Based Configuration**: Intuitive interface for all system settings

## 🏗️ Architecture Overview

```
ML-WAF System Architecture
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client        │───▶│   ML-WAF Proxy   │───▶│   Backend       │
│   Browser       │    │   (Port 8085)    │    │   Server        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   WAF Dashboard  │
                       │   (Port 5000)    │
                       └──────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   PostgreSQL     │
                       │   Database       │
                       └──────────────────┘
```

## 📋 System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 2GB free space
- **OS**: Linux/Windows/macOS
- **Network**: Stable internet connection

### Dependencies
- PostgreSQL 12+ (for logging and analytics)
- Modern web browser (for dashboard)

## 🛠️ Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/AnisDh25/ML-WAF.git
cd ML-WAF
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup
```bash
# Initialize PostgreSQL database
python init_postgresql.py

# Run migration (if upgrading from older version)
python migrate_to_postgres.py
```

### 5. Create Required Directories
```bash
mkdir -p models logs templates
```

### 6. Configure the System
Edit `config.json` to match your environment:
```json
{
    "database": {
        "host": "localhost",
        "port": "5432",
        "name": "waf_database",
        "user": "postgres",
        "password": "your_password"
    },
    "backend": {
        "host": "your-backend-server",
        "port": 80
    },
    "proxy": {
        "host": "127.0.0.1",
        "port": 8085
    }
}
```

## 🎯 Quick Start Guide

### Step 1: Train the ML Model
```bash
python train_model.py
```

### Step 2: Start the WAF Proxy
```bash
python ml_waf.py
```
The WAF proxy will start on `http://127.0.0.1:8085`

### Step 3: Start the Dashboard
In a new terminal:
```bash
python dashboard.py
```
Access the dashboard at `http://localhost:5000`
- Default credentials: admin/admin

### Step 4: Configure Browser Proxy
Set your browser's proxy settings to:
- **Host**: `127.0.0.1`
- **Port**: `8085`

## 📁 Project Structure

```
ML-WAF/
│
├── Core Components
│   ├── ml_waf.py                    # Main WAF proxy server
│   ├── feature_extractor.py         # Feature extraction for ML
│   ├── initial_waf_predictor.py      # ML classification engine
│   ├── content_filter.py            # Content filtering module
│   ├── popup_blocker.py             # Popup blocking module
│   └── auth.py                      # Authentication system
│
├── Database & Logging
│   ├── logger_module.py             # SQLite logging system
│   ├── logger_module_postgres.py    # PostgreSQL logging system
│   ├── database_config.py           # Database configuration
│   ├── init_postgresql.py           # Database initialization
│   └── migrate_to_postgres.py       # Migration utility
│
├── Dashboard & UI
│   ├── dashboard.py                 # Flask web dashboard
│   └── templates/                   # HTML templates
│       ├── base.html
│       ├── index.html
│       ├── logs.html
│       ├── alerts.html
│       ├── status.html
│       └── config.html
│
├── Machine Learning
│   ├── train_model.py               # Model training script
│   ├── simple_waf_trainer.py        # Advanced training utilities
│   ├── feature_adapter.py           # Feature adaptation utilities
│   └── models/                      # Trained models directory
│       └── waf_model.pkl
│
├── Testing & Utilities
│   ├── test_malicious_requests.py   # Security testing suite
│   ├── test_proxy_logging.py        # Proxy logging tests
│   ├── simple_test.py               # Basic functionality tests
│   └── convert_logs_to_training.py   # Log conversion utilities
│
├── Configuration
│   ├── config.json                  # Main configuration file
│   └── requirements.txt             # Python dependencies
│
└── Documentation
    ├── README.md                    # This file
    └── MIGRATION_GUIDE.md           # Database migration guide
```

## ⚙️ Configuration Options

### Machine Learning Settings
```json
"ml_classifier": {
    "model_path": "models/waf_model.pkl",
    "threshold": 0.7,              // Classification threshold (0.0-1.0)
    "features": [
        "url_length",
        "special_chars", 
        "suspicious_words",
        "path_depth",
        "query_params"
    ]
}
```

### Content Filter Configuration
```json
"content_filter": {
    "enabled": true,
    "blocked_patterns": [
        "script", "javascript:", "eval(",
        "alert(", "document.cookie"
    ],
    "blocked_extensions": [
        ".exe", ".bat", ".cmd", ".scr"
    ],
    "max_url_length": 2048,
    "allowed_methods": [
        "GET", "POST", "PUT", "DELETE"
    ]
}
```

### Popup Blocker Settings
```json
"popup_blocker": {
    "blocked_popup_triggers": [
        "window.open", "popup(", "alert("
    ],
    "blocked_attributes": [
        "target=_blank", "onclick", "onload"
    ]
}
```

### Security & Rate Limiting
```json
"security": {
    "rate_limit": {
        "enabled": true,
        "requests_per_minute": 100,
        "burst_size": 20
    },
    "ip_whitelist": ["127.0.0.1", "::1"],
    "blocked_ips": [],
    "session_timeout": 3600
}
```

## 📊 Dashboard Features

### 🏠 Home Dashboard
- **Real-time Statistics**: Live traffic metrics and attack analytics
- **Attack Distribution**: Pie charts showing attack types
- **Top Blocked IPs**: Most frequently blocked sources
- **Traffic Trends**: 24-hour traffic visualization
- **System Health**: Component status indicators

### 📋 Logs Viewer
- **Advanced Search**: Filter by IP, URL, method, host, or date range
- **Real-time Updates**: Live log streaming
- **Export Capabilities**: Download logs as CSV
- **Detailed Views**: Complete request/response analysis

### 🚨 Alerts System
- **Security Events**: Real-time threat notifications
- **Severity Filtering**: Critical, Warning, Info levels
- **Alert History**: Complete audit trail
- **Email Notifications**: Optional alert forwarding

### 🔧 Configuration Management
- **ML Threshold Adjustment**: Dynamic sensitivity tuning
- **Content Filter Rules**: Category and pattern management
- **IP Access Control**: Whitelist/blacklist management
- **Popup Blocker Settings**: Aggressiveness configuration
- **Backend Server Settings**: Target server configuration

### 📈 System Status
- **Component Health**: Real-time service monitoring
- **Database Connectivity**: Connection status and metrics
- **ML Model Status**: Model loading and performance
- **Resource Usage**: CPU, memory, and disk utilization

## 🧪 Testing & Validation

### Basic Functionality Tests
```bash
# Test benign request
python simple_test.py

# Test malicious request detection
python test_malicious_requests.py

# Test proxy logging
python test_proxy_logging.py
```

### Manual Testing with curl
**Benign Request:**
```bash
curl -x http://127.0.0.1:8085 http://example.com
```

**SQL Injection Test:**
```bash
curl -x http://127.0.0.1:8085 "http://example.com/page.php?id=1' OR '1'='1"
```

**XSS Test:**
```bash
curl -x http://127.0.0.1:8085 "http://example.com/search?q=<script>alert('XSS')</script>"
```

**Path Traversal Test:**
```bash
curl -x http://127.0.0.1:8085 "http://example.com/file=../../../etc/passwd"
```

## 📈 Model Training & Improvement

### Training with Existing Data
```bash
python train_model.py
```
The script automatically loads and processes logs from the database

### Custom Training Data
```python
# Add your custom datasets to train_model.py
benign_requests = [
    "GET /home HTTP/1.1",
    "POST /login HTTP/1.1",
    # ... more benign examples
]

malicious_requests = [
    "GET /?id=1' OR '1'='1 HTTP/1.1",
    "POST /search?q=<script>alert()</script> HTTP/1.1",
    # ... more malicious examples
]
```

### Feature Engineering
The system extracts these features for ML classification:
- **URL Length**: Total characters in the request URL
- **Special Characters**: Count of suspicious characters (`<`, `>`, `"`, `'`, `;`, `(`, `)`)
- **Suspicious Words**: Presence of attack keywords
- **Path Depth**: Number of directory levels
- **Query Parameters**: Number and complexity of parameters

## 🔒 Security Best Practices

### Production Deployment
1. **Change Default Credentials**: Update admin password immediately
2. **Enable HTTPS**: Use SSL/TLS for dashboard access
3. **Network Segmentation**: Place WAF in DMZ
4. **Firewall Rules**: Restrict dashboard access to authorized IPs
5. **Regular Updates**: Keep dependencies and models updated

### Operational Security
1. **Model Retraining**: Update ML models weekly with new attack patterns
2. **Log Monitoring**: Review blocked requests daily
3. **Whitelist Management**: Maintain updated legitimate service lists
4. **Backup Configuration**: Regular config and database backups
5. **Performance Monitoring**: Monitor system resources and response times

## 🐛 Troubleshooting Guide

### Common Issues

**Model Not Loading**
```bash
# Retrain the model
python train_model.py

# Check model file exists
ls -la models/waf_model.pkl
```

**Database Connection Failed**
```bash
# Check PostgreSQL status
pg_isready -h localhost -p 5432

# Test connection
python -c "import psycopg2; print('Connection OK')"
```

**Backend Connection Issues**
- Verify backend server is running
- Check `config.json` backend settings
- Test connectivity: `telnet backend-host backend-port`

**Dashboard Not Accessible**
- Check port availability: `netstat -an | grep 5000`
- Verify Flask installation: `pip install flask`
- Check firewall rules

**Performance Issues**
- Monitor system resources: `htop` (Linux) or Task Manager (Windows)
- Check database query performance
- Review log file sizes
- Adjust ML threshold for better balance

### Debug Mode
Enable debug logging in `config.json`:
```json
"logging": {
    "level": "DEBUG"
}
```

## 📝 API Reference

### Statistics Endpoints
- `GET /api/stats` - Current system statistics
- `GET /api/logs` - Recent log entries
- `GET /api/alerts` - Recent security alerts

### Configuration Endpoints
- `POST /api/config/update` - Update system configuration
- `POST /api/content_filter/toggle` - Enable/disable content filter
- `POST /api/popup_blocker/toggle` - Enable/disable popup blocker

### Chart Data Endpoints
- `GET /api/chart/traffic` - Traffic trend data
- `GET /api/chart/attacks` - Attack distribution data
- `GET /api/chart/performance` - System performance metrics

### Authentication Endpoints
- `POST /login` - User authentication
- `POST /logout` - User session termination
- `GET /api/user/profile` - Current user information

## 🔄 Version History

### v2.0.0 (Current)
- **Enhanced ML Model**: Improved accuracy with feature engineering
- **PostgreSQL Integration**: Advanced logging and analytics
- **Real-time Dashboard**: Modern responsive UI with live updates
- **Advanced Content Filtering**: Category-based blocking
- **Popup Blocking**: JavaScript pattern detection
- **API Endpoints**: RESTful API for integration
- **Migration Tools**: Automated database migration

### v1.0.0 (Legacy)
- Basic ML-based threat detection
- SQLite logging
- Simple web interface
- Content filtering basics

## 🤝 Contributing Guidelines

We welcome contributions! Please follow these steps:

1. **Fork the Repository**
   ```bash
   git clone https://github.com/AnisDh25/ML-WAF.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Follow existing code style
   - Add tests for new features
   - Update documentation

4. **Test Thoroughly**
   ```bash
   python -m pytest tests/
   ```

5. **Submit Pull Request**
   - Provide clear description
   - Include test results
   - Document breaking changes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Author

**Anis Dhahri**  
- GitHub: [@AnisDh25](https://github.com/AnisDh25)
- Email: anis.dhaoui@tek-up.de

## 🙏 Acknowledgments

- **Scikit-learn**: Machine learning capabilities
- **Flask**: Web framework for dashboard
- **PostgreSQL**: Robust database solution
- **Bootstrap**: Responsive UI components
- **Chart.js**: Interactive data visualization
- **Python Community**: Excellent libraries and support

## 📮 Support & Community

For issues, questions, or contributions:

- **GitHub Issues**: [Open an issue](https://github.com/AnisDh25/ML-WAF/issues)
- **Discussions**: [Join our discussions](https://github.com/AnisDh25/ML-WAF/discussions)
- **Email**: anis.dhahri@example.com

## 🔗 Related Projects

- [OWASP ModSecurity Core Rule Set](https://github.com/coreruleset/coreruleset)
- [NAXSI](https://github.com/nbs-system/naxsi)
- [SQLMap](https://github.com/sqlmapproject/sqlmap)

---

**⚠️ Important Notice**: This project is designed for educational purposes and small-to-medium scale deployments. For large enterprise environments, consider commercial WAF solutions with dedicated support and SLA guarantees.

**🛡️ Security Reminder**: Always keep your WAF and its dependencies updated. Regular security audits and penetration testing are recommended for production deployments.