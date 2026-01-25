from logger_module import WAFLogger

# Test alert creation
logger = WAFLogger()

# Create some test alerts
logger.create_alert('127.0.0.1', 'ML Detection', 'HIGH', 'Test ML alert')
logger.create_alert('127.0.0.1', 'Content Filter', 'MEDIUM', 'Test content filter alert')
logger.create_alert('127.0.0.1', 'Popup Blocker', 'LOW', 'Test popup blocker alert')

# Check if alerts were created
alerts = logger.get_alerts(5)
print(f'Found {len(alerts)} alerts')

for i, alert in enumerate(alerts[:3]):
    print(f'  {i+1}. {alert["timestamp"]} - {alert["alert_type"]} ({alert["severity"]}) - {alert["message"]}')
